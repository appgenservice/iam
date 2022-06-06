## IAM Service

#### IAM Service handle Identity and access management of users.

This service contains three main modules

* User Management (Identify of a user) such as user name, password and details about the users

* Identify Management: validate user credentials and allow/disallow a user

* Access Management: Valid a logged in user has access to specific resource

For example: 
User Ram has access to /reports end point to perform GET/POST/PUT operation, but not DELETE 

For future,

It would be nice if IAM service can manage user access for OAuth 2.0 client (like Google/Microsoft) identity validated users.

For example: Ram logged through google OAuth 2.0. Soon after the login process, frontend/client call IAM service.
IAM Access Managed has access information of the OAuth 2.0 logged users, and does the acces management.