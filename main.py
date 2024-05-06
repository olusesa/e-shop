from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask import Flask, render_template, redirect, url_for, request, flash,session, jsonify
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, redirect, url_for, request, flash
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
import os
import stripe
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['STRIPE_PUBLIC_KEY'] = os.environ.get('STRIPE_PUBLIC_KEY')
app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY')

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

# Other routes for authentication, shopping cart, checkout, etc.

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    if 'cart' not in session:
        session['cart'] = {}
    if product_id in session['cart']:
        session['cart'][product_id] += 1
    else:
        session['cart'][product_id] = 1
    session.modified = True
    flash('Item added to cart successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/update_cart/<int:product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = request.form.get('quantity')
    session['cart'][product_id] = int(quantity)
    session.modified = True
    flash('Cart updated successfully!', 'success')
    return redirect(url_for('view_cart'))

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    product = Product.query.get_or_404(product_id)
    session['cart'].pop(product_id, None)
    session.modified = True
    flash('Item removed from cart successfully!', 'success')
    return redirect(url_for('view_cart'))

@app.route('/view_cart')
@login_required
def view_cart():
    cart_items = []
    total_price = 0
    for product_id, quantity in session.get('cart', {}).items():
        product = Product.query.get_or_404(product_id)
        total_price += product.price * quantity
        cart_items.append({'product': product, 'quantity': quantity})
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.is_admin:
                # Add product logic here
                return redirect(url_for('add_product'))
            elif not user.is_admin or not user:
                flash('You are not authorized to access this page', 'error')
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        # Process payment using Stripe API
        total_price = 0
        for product_id, quantity in session.get('cart', {}).items():
            product = Product.query.get_or_404(product_id)
            total_price += product.price * quantity

        try:
            # Set up Stripe
            stripe.api_key = app.config['STRIPE_SECRET_KEY']

            # Create a PaymentIntent
            payment_intent = stripe.PaymentIntent.create(
                amount=int(total_price * 100),  # Amount is in cents
                currency='usd',
                description='E-Shop Purchase',
                payment_method_types=['card'],
                metadata={'integration_check': 'accept_a_payment'},
            )
            return render_template('checkout.html', client_secret=payment_intent.client_secret)

        except Exception as e:
            flash('Payment initialization failed. Please try again.', 'error')
            return redirect(url_for('view_cart'))

    return render_template('checkout.html')

app.config['UPLOAD_FOLDER'] = 'static/product_images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']

        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        image = request.files['image']

        # If user does not select file, browser also
        # submit an empty part without filename
        if image.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        # If the file is allowed, save it
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Add product to database
            # Replace the following lines with your database logic
            product = Product(name=name, price=price, description=description, image_filename=filename)
            db.session.add(product)
            db.session.commit()

            flash('Product added successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid file format. Allowed formats are: png, jpg, jpeg, gif', 'error')
            return redirect(request.url)

    return render_template('add_product.html')

        # @app.route('/checkout', methods=['GET', 'POST'])
# @login_required
# def checkout():
#     if request.method == 'POST':
#         # Process payment using Paystack API
#         total_price = 0
#         for product_id, quantity in session.get('cart', {}).items():
#             product = Product.query.get_or_404(product_id)
#             total_price += product.price * quantity
#
#         amount_in_kobo = int(total_price * 100)  # Paystack API requires amount in kobo (1 NGN = 100 kobo)
#         payment_response = Transaction.initialize(amount=amount_in_kobo,
#                                                    email=current_user.email,
#                                                    reference=f'{current_user.username}-{os.urandom(6).hex()}')
#         if payment_response['status']:
#             flash('Payment initialized. Redirecting to payment page...', 'success')
#             return redirect(payment_response['data']['authorization_url'])
#         else:
#             flash('Payment initialization failed. Please try again.', 'error')
#             return redirect(url_for('view_cart'))
#
#     return render_template('checkout.html')


# Main
if __name__ == '__main__':
    app.run(debug=True)
