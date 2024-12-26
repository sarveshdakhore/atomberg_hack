# Project Setup and Usage

## Prerequisites
- Ensure you have Node.js and npm installed on your machine.
- Install PostgreSQL as the database.

## Installation
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Install all the required libraries using the following command:
  ```sh
  npm install
  ```

## Environment Setup
1. Create a `.env` file in the root directory of the project.
2. Set up your environment variables as shown below:
  ```env
  DB_URL=your_database_url
  EXP_TIME_JWT=72h  # 3 days
  EXP_TIME_OTP=300000  # 5 minutes
  SECRET_KEY=your_secret_key
  EMAIL=your_email
  EMAIL_PASSWORD=your_email_password
  GOOGLE_CLIENT_ID=your_google_client_id
  GOOGLE_CLIENT_SECRET=your_google_client_secret
  CALLBACK_URL=http://localhost:3000/sign/auth/google/callback
  ```

## Database Setup
1. Run the Prisma migration command to set up your database schema:
  ```sh
  npx prisma migrate dev
  ```
2. Generate the Prisma client:
  ```sh
  npx prisma generate
  ```
3. To overview and manage your database, use Prisma Studio:
  ```sh
  npx prisma studio
  ```

## Running the Application
1. Open a new terminal and start the development server:
  ```sh
  npm run dev
  ```
2. Ensure the server is running on port 3000.

## Testing
- Use Postman or Thunder Client to test the API endpoints. Import the collection provided in the project to get started with testing.

## Notes
- Make sure to keep the server running on port 3000 for the application to work correctly.
