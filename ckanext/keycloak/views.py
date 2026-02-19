import logging
from flask import Blueprint, session
from ckan.plugins import toolkit as tk
import ckan.lib.helpers as h
import ckan.model as model
from ckan.common import g
from ckan.views.user import set_repoze_user, RequestResetView
from ckanext.keycloak.keycloak import KeycloakClient
import ckanext.keycloak.helpers as helpers
from os import environ
from distutils.util import strtobool
from urllib.parse import urlencode

from ckanext.keycloak.authz import sync_keycloak_groups_and_roles_to_ckan

log = logging.getLogger(__name__)

def _asbool(v, default=False):
    if v is None:
        return default
    try:
        return bool(strtobool(str(v)))
    except Exception:
        return default

def enable_ckan_internal_login():
    v = tk.config.get('ckanext.keycloak.enable_ckan_internal_login', environ.get('CKANEXT__KEYCLOAK__ENABLE_CKAN_INTERNAL_LOGIN'))
    return _asbool(v, default=True)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')


server_url = tk.config.get('ckanext.keycloak.server_url', environ.get('CKANEXT__KEYCLOAK__SERVER_URL'))
client_id = tk.config.get('ckanext.keycloak.client_id', environ.get('CKANEXT__KEYCLOAK__CLIENT_ID'))
realm_name = tk.config.get('ckanext.keycloak.realm_name', environ.get('CKANEXT__KEYCLOAK__REALM_NAME'))
redirect_uri = tk.config.get('ckanext.keycloak.redirect_uri', environ.get('CKANEXT__KEYCLOAK__REDIRECT_URI'))
client_secret_key = tk.config.get('ckanext.keycloak.client_secret_key', environ.get('CKANEXT__KEYCLOAK__CLIENT_SECRET_KEY'))
verify_ssl_raw = tk.config.get('ckanext.keycloak.verify_ssl', environ.get('CKANEXT__KEYCLOAK__VERIFY_SSL'))

def _parse_verify_ssl(v):
    # default secure
    if v is None:
        return True
    s = str(v).strip()
    sl = s.lower()
    if sl in ('true', '1', 'yes', 'on'):
        return True
    if sl in ('false', '0', 'no', 'off'):
        return False
    # treat as CA bundle path
    return s

verify_ssl = _parse_verify_ssl(verify_ssl_raw)

client = KeycloakClient(server_url, client_id, realm_name, client_secret_key, ssl_verify=verify_ssl)

def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import login_user
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
    else:
        user_id = g.user
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(g.user_obj.name, g.user_obj.email))

def login():
    log.info("HIT keycloak gate: /user/login")
    return tk.redirect_to(tk.url_for('keycloak.sso'))

def sso():
    log.info("SSO Login")
    auth_url = None
    try:
        auth_url = client.get_auth_url(redirect_uri=redirect_uri)
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)

def sso_login():
    data = tk.request.args
    token = client.get_token(data['code'], redirect_uri)

    # Keycloakログアウト時の id_token_hint に使う
    id_token = token.get('id_token')
    if id_token:
        session['keycloak_id_token'] = id_token

    userinfo = client.get_user_info(token)
    log.info("SSO Login: {}".format(userinfo))
    if userinfo:
        user_dict = {
            'name': helpers.ensure_unique_username_from_email(userinfo['preferred_username']),
            'email': userinfo['email'],
            'password': helpers.generate_password(),
            'fullname': userinfo['name'],
            'plugin_extras': {
                'idp': 'keycloak'
            }
        }
        context = {"model": model, "session": model.Session}
        g.user_obj = helpers.process_user(user_dict)
        g.user = g.user_obj.name
        context['user'] = g.user
        context['auth_user_obj'] = g.user_obj

        sync_keycloak_groups_and_roles_to_ckan(context, g.user_obj, userinfo)

        response = tk.redirect_to(tk.url_for('user.me', context))

        _log_user_into_ckan(response)
        log.info("Logged in success")
        return response
    else:
        return tk.redirect_to(tk.url_for('user.login'))

def _keycloak_logout_url(post_logout_redirect_uri=None):
    # Keycloak OIDC end_session_endpoint
    base = f"{server_url}/realms/{realm_name}/protocol/openid-connect/logout"

    params = {}
    id_token = session.get('keycloak_id_token')
    if id_token:
        params['id_token_hint'] = id_token

    if post_logout_redirect_uri:
        params['post_logout_redirect_uri'] = post_logout_redirect_uri

    return base + ("?" + urlencode(params) if params else "")

def _post_logout_redirect_uri():
    try:
        return tk.url_for('user.logged_out_page', _external=True)
    except Exception:
        return tk.url_for('home.index', _external=True)

def logout():
    log.info("HIT keycloak gate: /user/logout")

    # 戻り先
    post_logout_redirect_uri = _post_logout_redirect_uri()

    # 先に Keycloak logout URL を作る
    kc_url = _keycloak_logout_url(post_logout_redirect_uri)

    # まず CKAN 側の logout
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import logout_user
        logout_user()
    else:
        # repoze 用
        resp = tk.redirect_to(kc_url)
        set_repoze_user(None, resp)
        session.pop('keycloak_id_token', None)
        return resp

    # Flask session 側も消す
    session.pop('keycloak_id_token', None)

    # 最後に Keycloak へ
    return tk.redirect_to(kc_url)

def reset_password():
    email = tk.request.form.get('user', None)
    if '@' not in email:
        log.info(f'User requested reset link for invalid email: {email}')
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.request_reset'))
    user = model.User.by_email(email)
    if not user:
        log.info(u'User requested reset link for unknown user: {}'.format(email))
        return tk.redirect_to(tk.url_for('user.login'))
    user_extras = user[0].plugin_extras
    if user_extras and user_extras.get('idp') in ('keycloak', 'google'):
        log.info(u'User requested reset link for SSO user: {}'.format(email))
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.login'))
    return RequestResetView().post()

keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/sso_login', view_func=sso_login)
keycloak.add_url_rule('/logout', view_func=logout, methods=['GET'])
keycloak.add_url_rule('/_logout', view_func=logout, methods=['POST'])
keycloak.add_url_rule('/reset_password', view_func=reset_password, methods=['POST'])
if not enable_ckan_internal_login():
    keycloak.add_url_rule('/login', view_func=login, methods=['GET', 'POST'])

def get_blueprint():
    return keycloak