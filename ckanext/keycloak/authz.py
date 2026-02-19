# ckanext/keycloak/authz.py

import os
import re
import json
import logging
from typing import Optional, Set, Dict, Any

import ckan.plugins.toolkit as tk
from ckan import model
from ckan.logic import NotAuthorized

log = logging.getLogger(__name__)

# Keycloak group path:
#   /ckan/org/<org_name>
ORG_GROUP_RE = re.compile(r"^/ckan/org/(?P<org>[^/]+)$")

# Keycloak client role (existing role names):
#   admin / editor / member
ROLE_PRIORITY = {"admin": 3, "editor": 2, "member": 1}

# Store previously synced org list in user.plugin_extras to support revocation
SYNCED_ORGS_EXTRA_KEY = "keycloak_synced_orgs_v1"

# Keycloak role name to drive CKAN sysadmin flag
KEYCLOAK_SYSADMIN_ROLE = "sysadmin"


def _sysadmin_ctx(base_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a context that runs actions as CKAN sysadmin user specified by CKAN_SYSADMIN_NAME.
    Used as a fallback when ignore_auth is not honored for certain actions (e.g., delete).
    """
    sysadmin_name = os.environ.get("CKAN_SYSADMIN_NAME")
    if not sysadmin_name:
        raise RuntimeError("CKAN_SYSADMIN_NAME is not set")

    u = model.User.get(sysadmin_name)
    if not u:
        raise RuntimeError(f"Sysadmin user '{sysadmin_name}' not found")
    if not getattr(u, "sysadmin", False):
        raise RuntimeError(f"User '{sysadmin_name}' is not sysadmin")

    ctx = dict(base_context)
    ctx["user"] = u.name
    ctx["auth_user_obj"] = u
    ctx["ignore_auth"] = False  # be explicit
    return ctx


def _ignore_auth_ctx(base_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a context that bypasses authorization checks.
    In some environments this may not be honored for all actions; see _delete_org_member.
    """
    ctx = dict(base_context)
    ctx["ignore_auth"] = True
    return ctx


def _get_role_from_client_roles(userinfo: Dict[str, Any], client_id: str = "ckan") -> Optional[str]:
    """
    Extract the effective CKAN org role from Keycloak userinfo:
      userinfo.resource_access[client_id].roles -> choose max priority of admin/editor/member
    """
    ra = userinfo.get("resource_access") or {}
    roles = (ra.get(client_id) or {}).get("roles") or []
    if not isinstance(roles, list):
        return None

    candidates = [r for r in roles if r in ROLE_PRIORITY]
    if not candidates:
        return None

    return max(candidates, key=lambda r: ROLE_PRIORITY[r])  # admin > editor > member


def _has_keycloak_sysadmin_role(userinfo: Dict[str, Any], client_id: str = "ckan") -> bool:
    """
    Return True if Keycloak userinfo indicates sysadmin role for the given client.
    Expected location:
      userinfo.resource_access[client_id].roles contains 'sysadmin'
    """
    ra = userinfo.get("resource_access") or {}
    roles = (ra.get(client_id) or {}).get("roles") or []
    if not isinstance(roles, list):
        return False
    return KEYCLOAK_SYSADMIN_ROLE in roles


def _sync_ckan_sysadmin_flag(user_obj, should_be_sysadmin: bool) -> None:
    """
    Sync CKAN user's sysadmin flag to match Keycloak.
    This updates the user model directly (no user_update action), and commits immediately.

    NOTE: This is a "full sync":
      - True when Keycloak has sysadmin role
      - False otherwise
    """
    current = bool(getattr(user_obj, "sysadmin", False))
    if current == should_be_sysadmin:
        return

    user_obj.sysadmin = should_be_sysadmin
    model.Session.add(user_obj)
    model.Session.commit()

    log.info("Updated CKAN sysadmin flag: user=%s sysadmin=%s", user_obj.name, should_be_sysadmin)


def _get_orgs_from_groups(userinfo: Dict[str, Any]) -> Set[str]:
    """
    Extract org names from Keycloak group paths:
      userinfo.groups = ['/ckan/org/folder-a', ...] -> {'folder-a', ...}
    """
    groups = userinfo.get("groups") or []
    if not isinstance(groups, list):
        return set()

    orgs: Set[str] = set()
    for g in groups:
        m = ORG_GROUP_RE.match(g)
        if m:
            orgs.add(m.group("org"))
    return orgs


def _org_exists(ctx: Dict[str, Any], org_id: str) -> bool:
    """Return True if CKAN organization exists."""
    try:
        tk.get_action("organization_show")(ctx, {"id": org_id})
        return True
    except Exception:
        return False


def _ensure_org_member(ctx: Dict[str, Any], org_id: str, username: str, role: str) -> None:
    """
    Ensure a user is a member of an organization with the given role.
    We do delete->create to reliably update role.
    Supports CKAN environments where organization_member_create expects either 'role' or 'capacity'.
    """
    # Delete may fail when user is not a member; ignore.
    try:
        tk.get_action("organization_member_delete")(ctx, {"id": org_id, "username": username})
    except Exception:
        pass

    action = tk.get_action("organization_member_create")

    # Try 'role' first (often used in newer stacks / customizations)
    try:
        action(ctx, {"id": org_id, "username": username, "role": role})
        return
    except tk.ValidationError as e:
        log.warning("organization_member_create with role failed; retry with capacity. error=%s", e.error_dict)
    except Exception as e:
        log.warning("organization_member_create with role raised %s; retry with capacity", type(e).__name__)

    # Fallback to 'capacity' (older semantics)
    action(ctx, {"id": org_id, "username": username, "capacity": role})


def _delete_org_member(base_context: Dict[str, Any], org_id: str, username: str) -> bool:
    """
    Delete an org membership. Try ignore_auth first, and if that is rejected, fallback to sysadmin.
    Returns True on success.
    """
    action = tk.get_action("organization_member_delete")

    # 1) Try ignore_auth
    ctx_ignore = dict(base_context)
    ctx_ignore["ignore_auth"] = True

    try:
        action(ctx_ignore, {"id": org_id, "username": username})
        log.info("organization_member_delete success (ignore_auth): org=%s user=%s", org_id, username)
        return True
    except NotAuthorized as e:
        log.warning(
            "organization_member_delete NotAuthorized under ignore_auth; fallback to sysadmin. err=%s",
            str(e),
        )
    except Exception as e:
        log.warning("organization_member_delete failed under ignore_auth; fallback to sysadmin. err=%r", e)

    # 2) Sysadmin fallback (uses CKAN_SYSADMIN_NAME)
    try:
        ctx_admin = _sysadmin_ctx(base_context)
        action(ctx_admin, {"id": org_id, "username": username})
        log.info("organization_member_delete success (sysadmin): org=%s user=%s", org_id, username)
        return True
    except Exception as e:
        log.error("organization_member_delete failed even as sysadmin: org=%s user=%s err=%r", org_id, username, e)
        return False


def _read_synced_orgs_from_user(user_obj) -> Set[str]:
    """
    Read previously synced org list from user.plugin_extras.
    """
    extras = getattr(user_obj, "plugin_extras", None) or {}
    raw = extras.get(SYNCED_ORGS_EXTRA_KEY)
    if not raw:
        return set()

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return {x for x in data if isinstance(x, str)}
    except Exception:
        pass

    return set()


def _write_synced_orgs_to_user_model(user_obj, orgs: Set[str]) -> None:
    """
    Persist synced org list into user.plugin_extras using model update (avoids user_update validation issues).
    """
    extras = dict(getattr(user_obj, "plugin_extras", None) or {})
    extras[SYNCED_ORGS_EXTRA_KEY] = json.dumps(sorted(orgs), ensure_ascii=False)
    user_obj.plugin_extras = extras

    model.Session.add(user_obj)
    model.Session.commit()


def sync_keycloak_groups_and_roles_to_ckan(context: Dict[str, Any], user_obj, userinfo: Dict[str, Any]) -> None:
    """
    Main sync entrypoint to be called after CKAN user is resolved (during SSO login).

    Source of truth:
      - Keycloak client role (sysadmin): sysadmin -> CKAN user.sysadmin flag
      - If user is sysadmin: org sync is skipped (not needed)
      - Otherwise:
          - Keycloak groups: /ckan/org/<org_name>  -> organization.name
          - Keycloak client roles (client_id=ckan): admin/editor/member -> org role

    Behavior:
      0) Sync CKAN sysadmin flag from Keycloak role 'sysadmin'
      0b) If sysadmin=True, revoke previously synced org memberships and skip org sync
      1) Add/update memberships for orgs in Keycloak groups (non-sysadmin only)
      2) Revoke memberships that were previously synced but are no longer present (non-sysadmin only)
      3) Persist synced org list into user.plugin_extras (non-sysadmin only)
    """
    ctx = _ignore_auth_ctx(context)
    client_id = tk.config.get("ckanext.keycloak.client_id", "ckan")

    # 0) Sync sysadmin flag (user attribute)
    try:
        should_be_sysadmin = _has_keycloak_sysadmin_role(userinfo, client_id=client_id)
        _sync_ckan_sysadmin_flag(user_obj, should_be_sysadmin)
    except Exception:
        log.exception("Failed to sync CKAN sysadmin flag from Keycloak role")
        # If sysadmin sync fails, fall back to org sync path as before.
        should_be_sysadmin = False

    username = user_obj.name

    # 0b) If sysadmin: org sync is not needed. Clean up previously synced org memberships.
    if should_be_sysadmin:
        prev_synced = _read_synced_orgs_from_user(user_obj)
        if prev_synced:
            log.info("User is sysadmin; revoking previously synced org memberships: user=%s orgs=%s",
                     username, sorted(prev_synced))
        for org in sorted(prev_synced):
            if _delete_org_member(context, org_id=org, username=username):
                log.info("Revoked (sysadmin cleanup): org=%s user=%s", org, username)
            else:
                log.error("Revoke failed (sysadmin cleanup): org=%s user=%s", org, username)

        # Clear stored list
        try:
            _write_synced_orgs_to_user_model(user_obj, set())
        except Exception:
            log.exception("Failed to clear synced org list for sysadmin user")

        log.info("User is sysadmin; skipping org sync: user=%s", username)
        return

    # ---- non-sysadmin path below ----

    role = _get_role_from_client_roles(userinfo, client_id=client_id)
    orgs_from_keycloak = _get_orgs_from_groups(userinfo)

    log.info("Keycloak sync(ignore_auth): client_id=%s role=%s orgs=%s", client_id, role, sorted(orgs_from_keycloak))

    # Safety: if org role is missing, do nothing (no add/update/revoke)
    if not role:
        log.info("No role (admin/editor/member) in Keycloak client roles; skip add/update/revoke")
        return

    # 1) Add/Update
    effective_orgs: Set[str] = set()
    for org in orgs_from_keycloak:
        if not _org_exists(ctx, org):
            log.warning("Organization '%s' not found; skip", org)
            continue
        _ensure_org_member(ctx, org_id=org, username=username, role=role)
        effective_orgs.add(org)
        log.info("Synced: org=%s user=%s role=%s", org, username, role)

    # 2) Revoke: previous_synced - current_effective
    prev_synced = _read_synced_orgs_from_user(user_obj)
    revoke_orgs = prev_synced - effective_orgs

    for org in sorted(revoke_orgs):
        if _delete_org_member(context, org_id=org, username=username):
            log.info("Revoked: org=%s user=%s", org, username)
        else:
            log.error("Revoke failed: org=%s user=%s", org, username)

    # 3) Persist current effective org list
    try:
        _write_synced_orgs_to_user_model(user_obj, effective_orgs)
    except Exception:
        log.exception("Failed to persist synced org list to user plugin_extras (model update)")
