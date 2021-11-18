"""Collection of graphql schema."""

FIND_USER = """
query FindUser($username: String, $phone_number: String) {
  users(where: {_or: [{username: {_eq: $username}}, {phone_number: {_eq: $phone_number}}]}) {
    id
    email
    username
    phone_number
    role
    employs {
      organization
    }
    password
    is_active
    is_email_verified
    last_login
  }
}
"""

CREATE_USER = """
mutation CreateUser($email: String, $first_name: String, $gender: users_gender_enum, $password: String, $username: String, $last_name: String, $phone_number: String, $role: users_role_enum, $last_login: timestamptz) {
  insert_users_one(object: {email: $email, first_name: $first_name, gender: $gender, password: $password, username: $username, last_name: $last_name, phone_number: $phone_number, role: $role, last_login: $last_login}) {
    id
  }
}"""

GET_USER = """
query GetUser($id: uuid = "%s") {
  users_by_pk(id: $id) {
    id
    email
    username
    password
    is_active
    is_email_verified
    is_superuser
    last_login
  }
}
"""

CHANGE_USER_PASSWORD = """
mutation ChangeUserPassword($id: uuid = "%(user_id)s", $password: String = "%(new_password)s") {
  update_users_by_pk(pk_columns: {id: $id}, _set: {password: $password}) {
    id
  }
}
"""


VERIFY_USER_EMAIL = """
mutation VerifyUserEmail($id: uuid = "%(user_id)s", $is_email_verified: Boolean = "%(is_email_verified)s") {
  update_users_by_pk(pk_columns: {id: $id}, _set: {is_email_verified: $is_email_verified}) {
    id
  }
}
"""


LAST_LOGIN = """
mutation LastLogin($id: uuid = "%(user_id)s", $last_login: timestamptz = "%(last_login)s") {
  update_users_by_pk(pk_columns: {id: $id}, _set: {last_login: $last_login}) {
    last_login
  }
}
"""


CHANGE_USER_EMAIL = """
mutation ChangeUserEmail($id: uuid = "%(user_id)s", $email: String = "%(email)s") {
  update_users_by_pk(pk_columns: {id: $id}, _set: {email: $email, is_email_verified: false}) {
    id
  }
}
"""


ADD_EMPLOY = """
mutation AddEmploy($organization: uuid = "%(organization_id)s", $user: uuid = "%(user_id)s") {
  insert_employ_one(object: {user: $user, organization: $organization}) {
    id
  }
}
"""
