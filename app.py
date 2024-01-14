from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from bson import ObjectId

from Crypto.Cipher import DES
import hashlib

from dotenv import load_dotenv
import os

app = Flask(__name__)
load_dotenv()
app.secret_key = os.environ.get('SECRET_KEY')  # Oturum anahtarını tanımlayın

# MongoDB bağlantısı
client = MongoClient(os.environ.get('MONGO_URI'))
db = client["secure_teams"]
users_collection = db["users"]
messages_collection = db["messages"]
channels_collection = db["channels"]
groups_collection = db["group"]
background_image_path = '/static/background_image.jpg'  # Arka plan resminin yolunu belirleyin

# DES için kullanılacak anahtar (8 byte)
encryption_key = hashlib.sha1(os.environ.get('ENCRYPTION_KEY').encode()).digest()[:8]



def encrypt_password(password):
    cipher = DES.new(encryption_key, DES.MODE_ECB)
    padded_password = password + ' ' * (8 - len(password) % 8)
    encrypted_password = cipher.encrypt(padded_password.encode('utf-8'))
    return encrypted_password

# DES ile şifrelenmiş şifreyi karşılaştırma fonksiyonu
def check_password(entered_password, hashed_password):
    cipher = DES.new(encryption_key, DES.MODE_ECB)
    decrypted_password = cipher.decrypt(hashed_password).rstrip().decode('utf-8')
    return entered_password == decrypted_password

# DES ile şifreleme fonksiyonu
def encrypt_message(message):
    cipher = DES.new(encryption_key, DES.MODE_ECB)
    # Veri bloğunu 8 byte'a tamamlayacak şekilde dolduruluyor
    length = DES.block_size - (len(message) % DES.block_size)
    padded_message = message + chr(length) * length
    encrypted_message = cipher.encrypt(padded_message.encode('utf-8'))
    return encrypted_message

# DES ile şifrelenmiş mesajı çözme fonksiyonu
def decrypt_message(encrypted_message):
    cipher = DES.new(encryption_key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    # Eski padding'i kaldırmak için son bytedan padding boyutunu alıp kesebiliriz
    padding_size = ord(decrypted_message[-1])
    return decrypted_message[:-padding_size]


@app.route('/')
def index():

    return render_template('login.html', background_image_path=background_image_path)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        entered_username = request.form['username']
        entered_password = request.form['password']
        session['username'] = entered_username
        user = users_collection.find_one({'username': entered_username})

        if entered_username == "admin" and entered_password == "admin":
            return redirect(url_for('admin'))
        elif user:
            hashed_password = user['password']
            if check_password(entered_password, hashed_password):
                if user['role'] == "Teacher":
                    return redirect(url_for('teacher'))
                elif user['role'] == "Student":
                    return redirect(url_for('student'))
                else:
                    return redirect(url_for('home'))
            else:
                error_message = "Invalid username or password."
                return render_template('login.html', error=error_message, background_image_path=background_image_path)
        else:
            error_message = "Invalid username or password."
            return render_template('login.html', error=error_message, background_image_path=background_image_path)



@app.route('/home')
def home():
    return "Welcome, succesful login."

@app.route('/admin')
def admin():
    all_users = users_collection.find()  # Tüm kullanıcıları al
    return render_template('admin.html', users=all_users, background_image_path=background_image_path)

@app.route('/add_user', methods=['POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        usertype = request.form['role']
        print("1")
        hashed_password = encrypt_password(password)

        new_user = {
            'username': username,
            'password': hashed_password,
            'role': usertype
        }
        users_collection.insert_one(new_user)
        return redirect(url_for('admin'))


# Verilerin eski anahtarla çözülüp yeni anahtarla şifrelenmesi
def reencrypt_data(old_key, new_key):
    # Eski anahtarla şifrelenmiş verileri al
    encrypted_data = messages_collection.find({}, {'encrypted_field': 1})  # Şifrelenmiş verilerin bulunduğu alanı seçin

    for data in encrypted_data:
        encrypted_message = data['encrypted_field']
        # Eski anahtarla çözme işlemi
        old_cipher = DES.new(old_key, DES.MODE_ECB)
        decrypted_message = old_cipher.decrypt(encrypted_message).decode('utf-8')

        # Yeni anahtarla şifreleme işlemi
        new_cipher = DES.new(new_key, DES.MODE_ECB)
        length = DES.block_size - (len(decrypted_message) % DES.block_size)
        padded_message = decrypted_message + chr(length) * length
        reencrypted_message = new_cipher.encrypt(padded_message.encode('utf-8'))

        # Veritabanında güncelleme
        messages_collection.update_one(
            {'_id': data['_id']},
            {'$set': {'encrypted_field': reencrypted_message}}
        )

# Anahtar değiştirme fonksiyonu
def update_des_key(new_key):
    global encryption_key  # Anahtar değişkenini global olarak tanımlayın
    encryption_key = new_key  # Yeni anahtarı atayın

    # Veritabanındaki tüm şifrelenmiş verileri güncelleyin
    # Eski anahtarla çözüp, yeni anahtarla şifreleme işlemi yapılabilir

    # Örnek kullanım
    old_key = hashlib.sha1(b'10101010').digest()[:8]
    reencrypt_data(old_key, new_key)

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    users_collection.delete_one({'_id': ObjectId(user_id)})
    return redirect(url_for('admin'))


@app.route('/teacher', methods=['GET', 'POST'])
def teacher():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']

    if request.method == 'POST':
        if 'create_group' in request.form:
            group_name = request.form['group_name']
            group_description = request.form['group_description']
            teacher_username = username

            new_group = {
                'group_name': group_name,
                'group_description': group_description,
                'teacher_username': teacher_username,
                'students': [],  # Boş öğrenci listesi
                'teachers': []
            }
            groups_collection.insert_one(new_group)

        elif 'add_students' in request.form:
            group_id = request.form['group_id']
            selected_students = request.form.getlist('students')

            # Seçilen öğrencileri gruplara ekleme işlemi
            groups_collection.update_one(
                {'_id': ObjectId(group_id)},
                {'$addToSet': {'students': {'$each': [ObjectId(student) for student in selected_students]}}}
            )
        elif 'add_teacher' in request.form:
            group_id = request.form['group_id']
            selected_teachers = request.form.getlist('teachers')

            # Seçilen öğrencileri gruplara ekleme işlemi
            groups_collection.update_one(
                {'_id': ObjectId(group_id)},
                {'$addToSet': {'teachers': {'$each': [ObjectId(teacher) for teacher in selected_teachers]}}}
            )

    student_list = users_collection.find({'role': 'Student'}, {'_id': 1, 'username': 1})
    teacher_groups = groups_collection.find({'teacher_username': username})

    return render_template('teacher.html', username=username, student_list=student_list, teacher_groups=teacher_groups, background_image_path=background_image_path)


@app.route('/teacher/create_group', methods=['POST'])
def create_group():
    if request.method == 'POST':
        group_name = request.form['group_name']
        new_group = {
            'group_name': group_name,
            'teacher': session['username'],
            'students': []
        }
        group_id = groups_collection.insert_one(new_group).inserted_id

        # Gruba özgü bir sohbet koleksiyonu oluştur
        chat_collection_name = f"chat_{group_name.replace(' ', '_')}"  # Grup adından benzersiz bir koleksiyon adı oluştur
        db.create_collection(chat_collection_name)  # Koleksiyonu oluştur

        return redirect(url_for('teacher'))
    else:
        return render_template('teacher.html', background_image_path=background_image_path)



@app.route('/teacher/add_student', methods=['POST'])
def add_student():
    if request.method == 'POST':
        group_id = request.form['group_id']
        student_username = request.form['student_username']
        # Öğrenciyi belirli bir gruba ekleme
        groups_collection.update_one(
            {'group_name': group_id},
            {'$push': {'students': student_username}}
        )

        return redirect(url_for('teacher'))
    else:
        return render_template('teacher.html', background_image_path=background_image_path)

@app.route('/teacher/add_teacher', methods=['POST'])
def add_teacher():
    if request.method == 'POST':
        group_id = request.form['group_id']
        teacher_username = request.form['teacher_username']
        # Öğrenciyi belirli bir gruba ekleme
        groups_collection.update_one(
            {'group_name': group_id},
            {'$push': {'teachers': teacher_username}}
        )

        return redirect(url_for('teacher'))
    else:
        return render_template('teacher.html',background_image_path=background_image_path)


@app.route('/student', methods=['POST', 'GET'])
def student():
    if request.method == 'GET':
        if 'username' not in session:
            return redirect(url_for('index'))

        username = session['username']

        # Öğrencinin ekli olduğu grupları al
        student_groups = groups_collection.find({'students': username})

        return render_template('student.html', username=username, student_groups=student_groups, background_image_path=background_image_path)
    else:

        parent_group_name = request.form['parent_group_name']  # Ana grup adını al
        subgroup_name = request.form['subgroup_name']

        # Grup adına göre grup bulma
        parent_group = groups_collection.find_one({'group_name': parent_group_name})

        if parent_group:
            parent_group_id = parent_group['_id']

            new_subgroup = {
                'group_name': subgroup_name,
                'teacher_username': session['username'],
                'students': parent_group.get('students', []),
                'teachers': parent_group.get('teachers', [])
            }

            # Alt grubu ekleme işlemi
            groups_collection.update_one(
                {'_id': ObjectId(parent_group_id)},
                {'$push': {'subgroups': new_subgroup}}
            )
            return redirect(url_for('student'))
        else:
            # Eğer belirtilen grup adıyla eşleşen bir grup yoksa bir işlem yapılabilir
            # Örneğin hata mesajı gösterilebilir veya isteği reddedebilirsiniz.
            return "There is no group like that."

        if 'username' not in session:
            return redirect(url_for('index'))

        username = session['username']

        # Öğrencinin ekli olduğu grupları al
        student_groups = groups_collection.find({'students': username})

        return render_template('student.html', username=username, student_groups=student_groups, background_image_path=background_image_path)




@app.route('/group/<group_id>/<subgroup_name>', methods=['GET', 'POST'])
def subgroup_chat(group_id, subgroup_name):
    username = session.get('username')

    group_info = groups_collection.find_one({'_id': ObjectId(group_id)})

    if group_info and username in group_info.get('students', []):
        subgroups = group_info.get('subgroups', [])
        subgroup_info = None

        for subgroup in subgroups:
            if subgroup['group_name'] == subgroup_name:
                subgroup_info = subgroup
                break

        if subgroup_info and username in subgroup_info.get('students', []):
            chat_collection_name = f"chat_{subgroup_info['group_name']}"
            chat_collection = db[chat_collection_name]

            if request.method == 'POST':
                message = request.form['message']
                encrypted_message = encrypt_message(message)
                chat_collection.insert_one({'sender': username, 'message': encrypted_message})
                return redirect(url_for('subgroup_chat', group_id=group_id, subgroup_name=subgroup_name))
            else:
                chat_collection_name = f"chat_{subgroup_info['group_name']}"
                chat_collection = db[chat_collection_name]

                group_messages = chat_collection.find()

                decrypted_messages = [{'sender': message['sender'], 'message': decrypt_message(message['message'])} for message in group_messages]

                return render_template('chat.html', group_info=subgroup_info, messages=decrypted_messages, username=username)

        else:
            return "Access Denied: You don't have permission to access this subgroup."
    else:
        return "Access Denied: You don't have permission to access this subgroup."



@app.route('/teacher/add_subgroup', methods=['POST'])
def add_subgroup():
    if request.method == 'POST':
        parent_group_name = request.form['parent_group_name']  # Ana grup adını al
        subgroup_name = request.form['subgroup_name']

        # Grup adına göre grup bulma
        parent_group = groups_collection.find_one({'group_name': parent_group_name})

        if parent_group:
            parent_group_id = parent_group['_id']

            new_subgroup = {
                'group_name': subgroup_name,
                'teacher_username': session['username'],
                'students': parent_group.get('students', []),
                'teachers': parent_group.get('teachers', [])
            }

            # Alt grubu ekleme işlemi
            groups_collection.update_one(
                {'_id': ObjectId(parent_group_id)},
                {'$push': {'subgroups': new_subgroup}}
            )
            return redirect(url_for('teacher'))
        else:
            # Eğer belirtilen grup adıyla eşleşen bir grup yoksa bir işlem yapılabilir
            # Örneğin hata mesajı gösterilebilir veya isteği reddedebilirsiniz.
            return "Belirtilen grup adıyla eşleşen bir grup bulunamadı."
    else:
        return render_template('teacher.html')



def inherit_roles_from_group(parent_group_id, subgroup_id):
    parent_group = groups_collection.find_one({'_id': ObjectId(parent_group_id)})

    if parent_group:
        parent_roles = parent_group.get('roles', [])

        groups_collection.update_one(
            {'_id': ObjectId(subgroup_id)},
            {'$set': {'roles': parent_roles}}
        )


if __name__ == '__main__':
    app.run(debug=True)


