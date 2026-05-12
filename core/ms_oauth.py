"""
Microsoft OAuth2 共享常量

被 ``core.outlook_service`` (``get_ms_token``) 与 ``core.password_change_service``
共用。
"""

MS_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
MS_REDIRECT_URI = "http://localhost:8766"
MS_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access"
MS_AUTH_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
MS_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
