from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200))  # Store Image URL


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)


@app.route('/product/<int:id>')
def product(id):
    product = db.session.get(Product, id) # Correct way to get the product
    if product is None:
        abort(404) # Or return render_template('404.html'), 404
    return render_template('product.html', product=product)


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if 'cart' not in session:
        session['cart'] = {}
    if request.method == 'POST':
        try:
            # product_id = int(request.form['product_id'])
            # correction versus original code
            product_id = request.form['product_id']
            quantity = int(request.form['quantity'])

            if int(product_id) < 0 or quantity < 1:
                return "Invalid product id or quantity"

            session['cart'][product_id] = session['cart'].get(product_id, 0) + quantity
            session.modified = True
            return redirect(url_for('cart'))
        except ValueError:
            return "Invalid input. Please enter numbers for product ID and quantity."

    cart_items = []
    total = 0
    for product_id, quantity in session['cart'].items():
        product = db.session.get(Product, product_id) # Correct way to get the product
        if product:
            cart_items.append({'product': product, 'quantity': quantity})
            total += product.price * quantity
    return render_template('cart.html', cart_items=cart_items, total=total)


# @app.route('/remove_from_cart/<int:product_id>')
# changed because product_id is int but in the cart session in managed as char
# The problem is that the keys in your session['cart'] dictionary are integers, but when you use product_id
# in session['cart'], Flask is still passing product_id as a string, even if you put <int:product_id> in the
# route, the route convert product_id in a integer but the value that are inside the dictionary are not converted.
@app.route('/remove_from_cart/<product_id>')
def remove_from_cart(product_id):
    if 'cart' in session and str(product_id) in session['cart']:
        del session['cart'][product_id]
        session.modified = True
    return redirect(url_for('cart'))


@app.route('/checkout')
@login_required
def checkout():
    if 'cart' in session and session['cart']:
        session['cart'] = {}  # Empty the cart after "checkout"
        session.modified = True
        return render_template('checkout.html')
    return redirect(url_for('cart'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            return 'Username already exists'
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        return 'Invalid username or password'
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('cart', None)  # Clear the cart from the session
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add some sample products if the database is empty
        if not Product.query.first():
            db.session.add_all([
                Product(name='Product 1', price=10.0, image='product1.jpg'),
                Product(name='Product 2', price=20.0, image='product2.jpg'),
                Product(name='Product 3', price=30.0, image='product3.jpg'),
            ])
            db.session.commit()
    app.run(debug=True)
