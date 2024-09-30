# SourceBox Central Authentication API

<br/>
<br/>

> The SourceBox Central Authentication API is a user management and subscription service built using Flask and SQLAlchemy. This API provides secure user registration, login, and authentication using JWT tokens. It also includes functionality for managing user subscriptions via Stripe, tracking token usage, and handling CRUD operations for different data packs.

### The key features include

- User Registration, Login, and Authentication using JWT-based security.
- Token Management for tracking and managing API token usage.
- Premium User Management with Stripe integration for subscription handling.
- Pack Management for uploading and maintaining both text-based and code-based data packs.
- User History Tracking to log and retrieve user actions.
- Admin Capabilities for searching and managing users.


<br/>
<br/>
<br/>
<br/>

## Installation

<br/>

### Clone the Repository
```
git clone <repository_url>
cd sourcebox-central-auth-api
```
<br/>

### Set Up a Virtual Environment
```
python3 -m venv venv
source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
```
<br/>


### Install Dependencies
```
pip install -r requirements.txt
```

<br/>
<br/>
<br/>
<br/>

## Running the Application

<br/>

```
flask run
```
### or
```
flask run --port=5000
```


<br/>
<br/>
<br/>
<br/>


## API Endpoints

> he SourceBox Central Authentication API provides several RESTful endpoints for interacting with the platform.

<br/>

### User Registration

- Endpoint: /register
- Description: Registers a new user with a unique email and username.
- Method: POST

Payload Example:
```
{
  "email": "user@example.com",
  "username": "newuser",
  "password": "password123"
}
```
Response Example:
```
{
  "id": 1,
  "email": "user@example.com",
  "username": "newuser",
  "date_created": "2023-09-26T12:34:56",
  "premium_status": false
}
```

<br/>
<br/>

### User Login

Endpoint: /login
Description: Authenticates the user and retrieves an access token.
Method: POST

Payload Example:
```
{
  "email": "user@example.com",
  "password": "password123"
}
```
Response Example:
```
{
  "access_token": "<jwt_access_token>"
}
```

<br/>
<br/>


### Get User ID

- Endpoint: /user/id
- Description: Retrieves the user ID for the currently logged-in user.
- Method: GET

Response Example:
```
{
  "user_id": 1
}
```


<br/>
<br/>


### User History

- Endpoint: /user_history
- Description: Records and retrieves user actions.
- Method: POST or GET

Response Example:
```
[
  {
    "id": 1,
    "user_id": 1,
    "action": "Logged in",
    "timestamp": "2023-09-26T12:34:56"
  }
]
```


<br/>
<br/>


### Pack Management


- Endpoint: /packman/pack
- Description: Manages text-based data packs.
- Method: POST

Response Example:
```
{
  "id": 1,
  "user_id": 1,
  "pack_name": "Data Analysis Pack",
  "contents": [
    {
      "id": 1,
      "packman_id": 1,
      "content": "Sample text data",
      "data_type": "text",
      "filename": "sample.txt"
    }
  ]
}
```

<br/>
<br/>


### Code Pack Management


- Endpoint: /packman/code_pack
- Description: Manages code-based data packs.
- Method: POST

Response Example:
```
{
  "id": 1,
  "user_id": 1,
  "pack_name": "Code Analysis Pack",
  "contents": [
    {
      "id": 1,
      "packman_code_id": 1,
      "content": "def sample_function(): pass",
      "data_type": "python",
      "filename": "sample.py"
    }
  ]
}
```

<br/>
<br/>

### User Management

- List Users: /users (GET)
- Search Users: /users/search (GET)
- Delete User: /users/<int:user_id> (DELETE)
- Reset User Email: /users/<int:user_id>/email (PUT)
- Reset User Password: /users/<int:user_id>/password (PUT)


<br/>
<br/>


### Token Management
- Add Tokens: /user/add_tokens (POST)
- Get Token Usage: /user/token_usage (GET)


<br/>
<br/>


### Subscription Management (Stripe Integration)

- Set Stripe Subscription ID: /user/<int:user_id>/stripe/subscription (PUT)
- Cancel Stripe Subscription: /user/<int:user_id>/stripe/cancel_subscription (PUT)
- Get Stripe Subscription: /user/<int:user_id>/stripe_subscription (GET)

<br/>
<br/>

### Models and Schemas

<br/>

The API uses SQLAlchemy models to represent the following entities:


- User
- UserHistory
- PlatformUpdates
- Packman
- PackmanPack
- PackmanCode
- PackmanCodePack

<br/>

Each of these models has a corresponding Marshmallow schema for serialization and deserialization.

<br/>
<br/>
<br/>
<br/>

## Project Structure

The main components of the SourceBox Central Authentication API are organized as follows:

- app.py: Main application logic for routing and processing API requests.
- models.py: Defines SQLAlchemy models for the project.
- schemas.py: Defines Marshmallow schemas for model serialization.
- resources.py: Contains the business logic for each API endpoint.
- config.py: Manages application configuration settings.
- requirements.txt: Lists all necessary Python packages and libraries.


<br/>
<br/>
<br/>
<br/>


## Error Handling

The application handles errors using custom error handlers for the following scenarios:

- 404 Not Found: Handles resource not found errors.
- 500 Internal Server Error: Manages general server errors.
- SQLAlchemy Errors: Rolls back database sessions on SQL-related issues.


<br/>
<br/>
<br/>
<br/>


## Logging and Debugging

> Logging is configured to capture debug information, errors, and warnings. Log files are stored in the root directory as app.log. To adjust logging levels, modify the logging.basicConfig configuration in each file.



<br/>
<br/>
<br/>
<br/>

## License

<br/>

The SourceBox Central Authentication API is licensed under the MIT License. See the LICENSE file for more information.






