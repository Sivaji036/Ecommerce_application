from flask import Flask,render_template,request,redirect,session,url_for,flash,jsonify,make_response
import mysql.connector
import config
from flask_mail import Mail,Message
import random
import bcrypt
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
from datetime import timedelta
import razorpay
# from flask import request, jsonify, render_template
# import razorpay
import traceback
# from flask import make_response, render_template
from utils.pdf_generator import generate_pdf

app=Flask(__name__)
app.secret_key=config.SECRET_KEY
app.permanent_session_lifetime=timedelta(minutes=30)
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

app.config['MAIL_SERVER']=config.MAIL_SERVER
app.config['MAIL_PORT']=config.MAIL_PORT
app.config['MAIL_USE_TLS']=config.MAIL_USE_TLS
app.config['MAIL_USERNAME']=config.MAIL_USERNAME
app.config['MAIL_PASSWORD']=config.MAIL_PASSWORD

mail=Mail(app)
s=URLSafeTimedSerializer(app.secret_key)

def get_db_connection():
    conn=mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )
    return conn

@app.route('/')
def Home():
    if 'admin_id' in session:
        return redirect('/admin-dashboard')
    return redirect('/admin-login')

@app.route('/admin-signup',methods=['GET','POST'])
def admin_signup():
    if request.method=='GET':
        
        return render_template('admin/admin_signup.html')

    name=request.form['name'].strip()
    email=request.form['email'].strip()

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from admins where email=%s',(email,))
    row=cursor.fetchone()

    if row:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')
    
    session['username']=name
    session['email']=email

    otp=random.randint(100000,999999)

    session['otp']=otp
    message=Message(subject='SmartCart Admin OTP',sender=config.MAIL_USERNAME,recipients=[email])
    message.body=f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)
    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')

@app.route('/verify-otp',methods=['GET'])
def verify_otp_get():
    return render_template('admin/verify_otp.html')

@app.route('/verify-otp',methods=['GET','POST'])
def verify_otp():
    
        otp=request.form['otp']
        password=request.form['pwd']
        if str(otp)!=str(session['otp']):
            flash("Invalid OTP. Try again!", "danger")
            return redirect('/verify-otp')
        
        hass_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        conn=get_db_connection()
        cursor=conn.cursor(dictionary=True)
        cursor.execute('insert into admins(name,email,password) values(%s,%s,%s)',(session['username'],session['email'],hass_password))
        conn.commit()
        cursor.close()
        conn.close()
        session.pop('otp',None)
        session.pop('username',None)
        session.pop('email',None)
        flash("Admin Registered Successfully!", "success")
        return redirect('/admin-login') 
@app.route('/admin-login',methods=['GET','POST'])
def admin_login():
    if request.method=='GET':
           img='signin.jpg'
           return render_template('admin/admin_login.html',img=img)
      
    email=request.form['email'].strip()
    password=request.form['pwd']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from admins where email=%s',(email,))
    row=cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
         flash('Email not found register first')
         return redirect('/admin-signup')
    
    stored_hashed_password=row['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'),stored_hashed_password):
        flash('incorrect password!','danger')
        return redirect('/admin-login')
    
    session['admin_id']=row['admin_id']
    session['admin_name']=row['name']
    session['admin_email']=row['email']
    session.permanent=True

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')
@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        # flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')
    
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select count(*) as total from products')
    total_products = cursor.fetchone()['total']

    return render_template("admin/dashboard.html", admin_name=session['admin_name'],total_products=total_products)
@app.route('/admin/products')
def admin_products():
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products')
    products=cursor.fetchall()
    return render_template("admin/admin_products.html", products=products)
@app.route('/admin-logout')
def admin_logout():
     session.pop('admin_id',None)
     session.pop('admin_name',None)
     session.pop('admin_email', None)
     flash("Logged out successfully.", "success")
     return redirect('/admin-login')

UPLOAD_FOLDER='static/uploads/product_images'
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
@app.route('/admin/add-item',methods=['GET'])
def add_item_page():
    if 'admin_id' not in session:
          flash("please login first","danger")
          return redirect('/admin-login')
    return render_template('admin/add_item.html')
@app.route('/admin/add-item', methods=['POST'])
def add_item():
    if 'admin_id' not in session:
          flash('login first','danger')
          return redirect('/admin-login')
     
    name=request.form['name'].strip()
    description=request.form['description'].strip()
    category=request.form['category'].strip()
    price=request.form['price']
    image_file = request.files['image']

    
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    
    filename = secure_filename(image_file.filename)

    
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    
    image_file.save(image_path)

    
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (%s, %s, %s, %s, %s)",
        (name, description, category, price, filename)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')
@app.route('/admin/item-list')
def item_list():
     
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    search=request.args.get('search','')
    category_filter=request.args.get('category','')

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select DISTINCT category from products')
    categories=cursor.fetchall()

    query='select * from products where 1=1'
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")
    

    if category_filter:
        query += " AND category LIKE %s"
        params.append(category_filter)


    cursor.execute(query, params)
    products = cursor.fetchall()
    if not products:
        flash('product not found','danger')
    cursor.close()
    conn.close()
    return render_template('admin/item_list.html', products=products,categories=categories)
@app.route('/admin/view-item/<int:id>')
def view_item(id):
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products where product_id=%s',(id,))
    row=cursor.fetchone()
    conn.close()
    cursor.close()
    return render_template('/admin/view_item.html',row=row)
@app.route('/admin/update-item/<int:id>',methods=['GET'])
def update_item_page(id):
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products where product_id=%s',(id,))    
    row=cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template('/admin/update_item.html',product=row) 
@app.route('/admin/update-item/<int:id>',methods=['POST'])
def update_item(id):
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    name=request.form['name']
    description=request.form['description']
    category=request.form['category']
    price=request.form['price']
    new_image=request.files['image']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from products where product_id=%s',(id,))
    row=cursor.fetchone()
    

    if not row:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')
    

    old_image_name = row['image']

    
    if new_image and new_image.filename != "":
        
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        
        final_image_name = old_image_name

    cursor.execute('update products set name=%s,description=%s,category=%s,price=%s,image=%s where product_id=%s',(name,description,category,price,final_image_name,id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

@app.route('/forgot',methods=['GET'])
def forgot():
    return render_template('/admin/forgot_password.html')

@app.route('/verify_email',methods=['POST'])
def send_reset_link():
    
    email=request.form['email']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from admins where email=%s',(email,))
    row=cursor.fetchone()

    if not row:
        flash('please login','danger')
        return redirect('/admin-login')
    
    token=s.dumps(email,salt='password-reset-salt')
    link=f'http://localhost:5000/reset_password/{token}'

    msg=Message(subject='password reset link',sender=config.MAIL_USERNAME,recipients=[email])
    msg.body=f'click here to reset your password:{link}'
    mail.send(msg)
    flash('reset link sent to your email')
    return redirect('/admin-login')
@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_password(token):
    try:
        email=s.loads(token,salt='password-reset-salt',max_age=900)
    except SignatureExpired:
        return f"link experied try again"
    
    if request.method=='POST':
        password=request.form['pwd']
        cpassword=request.form['cpwd']

        if password!=cpassword:
            return f'password and confirm password is not same <a href="/reset_password/{token}">Try again</a>'
    
        hass_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        conn=get_db_connection()
        cursor=conn.cursor(dictionary=True)

        cursor.execute('update admins set password=%s where email=%s',(hass_password,email))
        flash('password update sucessfully','success')
        conn.commit()
        conn.close()
        cursor.close()
        return redirect('/admin-login')
    return render_template('/admin/reset_password.html') 
@app.route('/admin/delete-item/<int:id>')  
def delete_item(id):
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products where product_id=%s',(id,))
    row=cursor.fetchone()
    if not row:
        flash('no record found','danger')
        return redirect('/admin/item-list')
    
    image_name=row['image']
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)

    if os.path.exists(image_path):
        os.remove(image_path)

    cursor.execute('delete from products where product_id=%s',(id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')   
ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

@app.route('/admin/profile',methods=['GET'])
def admin_profile():
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    admin_id = session['admin_id']
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from admins where admin_id=%s',(admin_id,))
    admin=cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('/admin/admin_profile.html',admin=admin)
@app.route('/admin/profile',methods=['POST'])
def admin_profile_update():
    if 'admin_id' not in session:
        flash('please login first','danger')
        return redirect('/admin-login')
    
    admin_id = session['admin_id']

    name=request.form['name']
    email=request.form['email']
    new_password=request.form['password']
    new_image=request.files['profile_image']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from admins where admin_id=%s',(admin_id,))
    admin=cursor.fetchone()

    if not admin:
        flash('record not found','danger')
        return redirect('/admin/add-item')

    old_image_name = admin['profile_image']

    if new_password:
        hass_password=bcrypt.hashpw(new_password.encode('utf-8'),bcrypt.gensalt())
    else:
        hashed_password=admin['password']

    if new_image and new_image.filename != "":
        from werkzeug.utils import secure_filename
        new_filename=secure_filename(new_image.filename)

        image_path=os.path.join(app.config['ADMIN_UPLOAD_FOLDER'],new_filename)
        new_image.save(image_path)

        if old_image_name:
            old_image_path=os.path.join(app.config['ADMIN_UPLOAD_FOLDER'],old_image_name)
            if os.path.exists(old_image_name):
                os.remove(old_image_name)
        final_image_name = new_filename
    else:
            final_image_name=old_image_name

    cursor.execute("""
    UPDATE admins
    SET name=%s, email=%s, password=%s, profile_image=%s
    WHERE admin_id=%s
""", (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()
    session['name']=name
    session['email']=email
    
    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

@app.route('/admin/about')
def about():
    return render_template('/admin/about.html')

@app.route('/admin/contact')
def contact():
    return render_template('/admin/contact.html')

@app.route('/user-register',methods=['GET','POST'])
def user_register():
    if request.method=='GET':
        return render_template('user/user_registration.html')
    
    name=request.form['name']
    email=request.form['email']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from users where email=%s',(email,))
    row=cursor.fetchone()
    if row:
        flash('user already register please login','danger')
        return redirect('user-login')
    

    session['username']=name
    session['email']=email
    otp=random.randint(100000,999999)
    session['otp']=otp

    message=Message(subject='user signup otp',sender=config.MAIL_USERNAME,recipients=[email])
    message.body=f"Your OTP for SmartCart user Registration is: {otp}"
    mail.send(message)
    flash('otp sent to mail sucessfully','success')
    return redirect('/user-verify-otp')
@app.route('/user-verify-otp',methods=['GET','POST'])
def user_verify_otp():
    if request.method=='GET':
        return render_template('user/user_verify_otp.html')
    
    otp=request.form['otp']
    password=request.form['pwd']
    cpassword=request.form['cpwd']

    if str(session['otp'])!=otp:
        flash('Incorrect otp','danger')
        return redirect('user-verify-otp')
    
    if password!=cpassword:
        flash('incorrect password and confirm password')
        return redirect('user-verify-otp')
    
    hass_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('insert into users(name,email,password) values(%s,%s,%s)',(session['username'],session['email'],hass_password))
    conn.commit()
    conn.close()
    cursor.close()
    session.pop('otp',None)
    session.pop('username',None)
    session.pop('email',None)
    flash('registration completed sucessfully','success')
    return redirect('/user-login')
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['pwd']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')

@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products')
    products=cursor.fetchall()
    return render_template("user/user_home.html", user_name=session['user_name'],products=products)
@app.route('/user-forgot',methods=['GET'])
def user_forgot():
    return render_template('/user/forgot_password.html')
@app.route('/user-verify-email',methods=['POST'])
def user_send_reset_link():
    
    email=request.form['email']

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from users where email=%s',(email,))
    row=cursor.fetchone()

    if not row:
        flash('please login','danger')
        return redirect('/admin-login')
    
    token=s.dumps(email,salt='password-reset-salt')
    link=f'http://localhost:5000/user/reset_password/{token}'

    msg=Message(subject='password reset link',sender=config.MAIL_USERNAME,recipients=[email])
    msg.body=f'click here to reset your password:{link}'
    mail.send(msg)
    flash('reset link sent to your email')
    return redirect('/user-login')
@app.route('/user/reset_password/<token>',methods=['GET','POST'])
def  user_reset_password(token):
    try:
        email=s.loads(token,salt='password-reset-salt',max_age=900)
    except SignatureExpired:
        return f"link experied try again"
    
    if request.method=='POST':
        password=request.form['pwd']
        cpassword=request.form['cpwd']

        if password!=cpassword:
            return f'password and confirm password is not same <a href="/reset_password/{token}">Try again</a>'
    
        hass_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        conn=get_db_connection()
        cursor=conn.cursor(dictionary=True)

        cursor.execute('update users set password=%s where email=%s',(hass_password,email))
        flash('password update sucessfully','success')
        conn.commit()
        conn.close()
        cursor.close()
        return redirect('/user-login')
    return render_template('/user/reset_password.html')
@app.route('/user-logout')
def user_logout():
    session.pop(session['user_id'],None)
    session.pop(session['user_name'],None)
    session.pop(session['user_email'],None)
    flash('logout sucessfully','success')
    return redirect('/user-login')
@app.route('/user/products')
def user_products():
    if 'user_id' not in session:
        flash('please login first','danger')
        return redirect('/user-login')
    
    search=request.args.get('search','')
    category_filter=request.args.get('category','')

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products")
    categories=cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%"+search+"%")

    if category_filter:
        query += " AND category LIKE %s"
        params.append(category_filter)
    
    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/user_products.html",products=products,categories=categories)
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):
    if 'user_id' not in session:
        flash('please login first','danger')
        return redirect('/user-login')
    

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute('select * from products where product_id =%s',(product_id,))
    product=cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/user_product_details.html", product=product)

@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')
    
    if 'cart' not in session:
        session['cart']={}

    cart = session['cart']
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from products where product_id=%s',(product_id,))
    product=cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)
    
    pid = str(product_id)

    if pid in cart:
       cart[pid]['quantity'] += 1
    else:
        cart[pid]={
            'name':product['name'],
            'price':float(product['price']),
            'image':product['image'],
            'quantity': 1
        }
    
    session['cart']=cart
    flash("Item added to cart!", "success")
    return redirect(request.referrer)   

@app.route('/user/cart')
def view_cart():
    if 'user_id' not in session:
        flash('please login first','danger')
        return redirect('/user-login')
    
    cart=session.get('cart',{})

    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('user/user_cart.html',cart=cart,grand_total=grand_total)
@app.route('/user/cart/decrease/<pid>')
def cart_decrease(pid):
    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity']-=1

        if cart[pid]['quantity']<=0:
            cart.pop(pid)
    
    session['cart']=cart
    return redirect('/user/cart')
@app.route('/user/cart/increase/<pid>')
def cart_increase(pid):
    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity']+=1


    session['cart']=cart
    return redirect('/user/cart')
@app.route('/user/cart/remove/<pid>')   
def cart_remove(pid):
    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart']=cart
    flash("Item removed!", "success")
    return redirect('/user/cart')
@app.route('/user/pay',methods=['GET', 'POST'])
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )
@app.route('/user/pay/<int:product_id>', methods=['GET', 'POST'])
def user_pay_single(product_id):
    if 'user_id' not in session:
        flash('please login first','danger')
        return redirect('/user-login')
    
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute('select * from products where product_id=%s',(product_id,))
    product=cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')
    
    total_amount=product['price']
    razorpay_amount = int(total_amount * 100)

    razorpay_order=razorpay_client.order.create({
        "amount":razorpay_amount,
        "currency":"INR",
        "payment_capture": 1
    })
    session['razorpay_order_id'] = razorpay_order['id']
    session['single_product_id'] = product['product_id']
    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id'],
        product=product
    )
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )
@app.route('/payment-failure')
def payment_failure():
    
    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')
    error_msg = request.args.get('error')  

    
    session.pop('single_product_id', None)
    session.pop('razorpay_order_id', None)

    
    if error_msg:
        flash(f"Payment failed: {error_msg}", "danger")
    else:
        flash("Payment failed. Please try again.", "danger")

    
    return render_template(
        "user/payment_failure.html",
        payment_id=payment_id,
        order_id=order_id,
        error_msg=error_msg
    )
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read Razorpay POST data
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    user_id = session['user_id']

    # Read address data from form
    full_name = request.form.get('full_name')
    street_address = request.form.get('street_address')
    city = request.form.get('city')
    state = request.form.get('state')
    postal_code = request.form.get('postal_code')
    country = request.form.get('country')
    phone_number = request.form.get('phone_number')

    if not all([full_name, street_address, city, state, postal_code, country, phone_number]):
        flash("Please provide a complete shipping address.", "danger")
        return redirect('/user/cart')

    # Determine items to process: cart or single product
    cart = session.get('cart', {})

    if not cart and 'single_product_id' in session:
        product_id = session['single_product_id']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
        product = cursor.fetchone()
        cursor.close()
        conn.close()

        if not product:
            flash("Product not found!", "danger")
            return redirect('/user/products')

        cart = {
            str(product['product_id']): {
                'name': product['name'],
                'price': product['price'],
                'quantity': 1
            }
        }

    if not cart:
        flash("No items to purchase.", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # Store order and items in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Insert order including shipping address
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status,
                                full_name, street_address, city, state, postal_code, country, phone_number)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid',
              full_name, street_address, city, state, postal_code, country, phone_number))

        order_db_id = cursor.lastrowid

        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        conn.commit()

        # Clear sessions
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)
        session.pop('single_product_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s", str(e))
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()


@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response

if __name__=='__main__':
    app.run(debug=True)