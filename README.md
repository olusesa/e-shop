# E-Shop

E-Shop is a simple e-commerce web application built using Flask, PostgreSQL, Flask-Login, and Stripe API. It allows users to browse products, add them to a shopping cart, and proceed to checkout to make a payment.

## Features

- User authentication: Users can register, login, and logout.
- Product browsing: Users can browse through available products and view their details.
- Shopping cart: Users can add products to their shopping cart, update quantities, and remove items.
- Checkout: Users can proceed to checkout to make a payment using Stripe API.

## Prerequisites

Before running the application, make sure you have the following installed:

- Python 3.x
- PostgreSQL
- Stripe account (for processing payments)

## Installation

1. Clone the repository:

git clone https://github.com/olusesa/e-shop.git

2. Create a virtual environment and activate it:

cd e-shop
python3 -m venv venv
source venv/bin/activate


3. Install the required dependencies:


pip install -r requirements.txt


4. Set up the PostgreSQL database:

   - Create a new PostgreSQL database.
   - Set the `SQLALCHEMY_DATABASE_URI` in `app.py` to point to your PostgreSQL database.

5. Set up your Stripe API keys:

   - Create a Stripe account if you don't have one already.
   - Set the `STRIPE_PUBLIC_KEY` and `STRIPE_SECRET_KEY` environment variables in your terminal or `.env` file.

6. Run the application:

python main.py


## Usage

- Visit http://localhost:5000 in your web browser to access the application.
- Register an account or login if you already have one.
- Browse through available products, add them to your shopping cart, and proceed to checkout to make a payment.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

