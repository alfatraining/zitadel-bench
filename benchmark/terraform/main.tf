# Provider docs: https://registry.terraform.io/providers/zitadel/zitadel/2.0.1/docs
terraform {
  required_providers {
    zitadel = {
      source  = "zitadel/zitadel"
      version = "2.0.1"
    }
  }
}

locals {
  password       = "Password1!"
  zitadel_domain = "zitadel.127.0.0.1.nip.io"
  zitadel_port   = "8080"
  redirect_uris  = ["http://localhost:8081/login"]
  response_types = ["OIDC_RESPONSE_TYPE_CODE"]
  app_type       = "OIDC_APP_TYPE_WEB"
}

variable "concurrency" {
  default = 1
}

provider "zitadel" {
  domain           = local.zitadel_domain
  port             = local.zitadel_port
  insecure         = "true"
  jwt_profile_file = "/zitadel-machine-key/service-account-key.json"
}

resource "zitadel_org" "test_org" {
  name = "Test Organisation"
}

resource "zitadel_project" "test_project" {
  name                     = "Test Project"
  org_id                   = zitadel_org.test_org.id
  project_role_assertion   = true
  project_role_check       = true
  has_project_check        = true
  private_labeling_setting = "PRIVATE_LABELING_SETTING_ENFORCE_PROJECT_RESOURCE_OWNER_POLICY"
}

resource "zitadel_machine_user" "user_manager" {
  org_id      = zitadel_org.test_org.id
  user_name   = "user_manager@example.com"
  name        = "User manager"
  description = "User manager"
  with_secret = false
}

resource "zitadel_personal_access_token" "user_manager" {
  org_id          = zitadel_org.test_org.id
  user_id         = zitadel_machine_user.user_manager.id
  expiration_date = "2519-04-01T08:45:00Z"
}

resource "zitadel_org_member" "user_manager" {
  org_id  = zitadel_org.test_org.id
  user_id = zitadel_machine_user.user_manager.id
  roles   = ["ORG_USER_MANAGER"]
}

resource "zitadel_application_oidc" "pkcse" {
  grant_types             = ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN", "OIDC_GRANT_TYPE_TOKEN_EXCHANGE"]
  name                    = "IAM service (Authentication) PKCSE"
  project_id              = zitadel_project.test_project.id
  redirect_uris           = local.redirect_uris
  response_types          = local.response_types
  org_id                  = zitadel_org.test_org.id
  id_token_role_assertion = true
  app_type                = local.app_type
  auth_method_type        = "OIDC_AUTH_METHOD_TYPE_NONE"
}

resource "zitadel_application_oidc" "jwt" {
  grant_types                 = ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN", "OIDC_GRANT_TYPE_TOKEN_EXCHANGE"]
  name                        = "IAM service (Authentication) JWT"
  project_id                  = zitadel_project.test_project.id
  redirect_uris               = local.redirect_uris
  response_types              = local.response_types
  org_id                      = zitadel_org.test_org.id
  app_type                    = local.app_type
  auth_method_type            = "OIDC_AUTH_METHOD_TYPE_PRIVATE_KEY_JWT"
  access_token_type           = "OIDC_TOKEN_TYPE_JWT"
  access_token_role_assertion = true
}

resource "zitadel_application_key" "jwt" {
  org_id          = zitadel_org.test_org.id
  project_id      = zitadel_project.test_project.id
  app_id          = zitadel_application_oidc.jwt.id
  key_type        = "KEY_TYPE_JSON"
  expiration_date = "2519-04-01T08:45:00Z"
}

resource "local_file" "pkcse" {
  content = format(<<EOF
ADDR=%s
CLIENT_ID=%s
MACHINE_ACCESS_TOKEN=%s
MACHINE_USER_ID=%s
PASSWORD=%s
REDIRECT_URI=%s
METRICS_URI=%s
CONCURRENCY=%s
COUNT=0
EOF
    ,
    format("http://%s:%s", "zitadel.127.0.0.1.nip.io", local.zitadel_port),
    zitadel_application_oidc.pkcse.client_id,
    zitadel_personal_access_token.user_manager.token,
    zitadel_machine_user.user_manager.id,
    local.password,
    zitadel_application_oidc.pkcse.redirect_uris[0],
    "0.0.0.0:9090",
    var.concurrency,
  )
  filename = "${path.module}/.env_pkcse"
}

resource "local_file" "jwt" {
  content = format(<<EOF
ADDR=%s
CLIENT_ID=%s
MACHINE_ACCESS_TOKEN=%s
MACHINE_USER_ID=%s
PASSWORD=%s
REDIRECT_URI=%s
METRICS_URI=%s
CONCURRENCY=%s
COUNT=0
PRIVATE_KEY='%s'
EOF
    ,
    format("http://%s:%s", "zitadel.127.0.0.1.nip.io", local.zitadel_port),
    zitadel_application_oidc.jwt.client_id,
    zitadel_personal_access_token.user_manager.token,
    zitadel_machine_user.user_manager.id,
    local.password,
    zitadel_application_oidc.jwt.redirect_uris[0],
    "0.0.0.0:9090",
    var.concurrency,
    zitadel_application_key.jwt.key_details,
  )
  filename = "${path.module}/.env_jwt"
}
