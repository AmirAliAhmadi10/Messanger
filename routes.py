import secrets
import os
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from .app import create_app
from .extensions import socketio, bcrypt
from .models import *
from .forms import *
from PIL import Image
from datetime import datetime
from sqlalchemy import or_
from PIL import UnidentifiedImageError
from jaasJWT import JaaSJwtBuilder

file_dir = os.path.dirname(__file__)
app = create_app()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter(db.func.lower(User.username) == db.func.lower(username)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    # Initialize photo_filename with a default value
    photo_filename = 'default.jpg'

    if form.validate_on_submit():
        print("Validation successful")
        username = form.username.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data

        if 'profile_image' in request.files and form.profile_image.data:
            try:
                profile_image = request.files['profile_image']
                photo_filename = save_profile_picture(profile_image, current_user)
                print(f"Saved profile image: {photo_filename}")
            except UnidentifiedImageError as e:
                flash('Invalid image file. Please upload a valid image.', 'danger')
                return redirect(url_for('register'))

        existing_user = User.query.filter(
            db.func.lower(User.username) == db.func.lower(username) |
            db.func.lower(User.email) == db.func.lower(email)
        ).first()

        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                username=username,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                email=email,
                profile_image=photo_filename
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)


def save_profile_picture(form_picture, user):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_filename = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], picture_filename)

    # Open the image using PIL
    img = Image.open(form_picture)

    # Crop the image to a square
    min_side = min(img.size)
    left = (img.size[0] - min_side) / 2
    top = (img.size[1] - min_side) / 2
    right = (img.size[0] + min_side) / 2
    bottom = (img.size[1] + min_side) / 2
    img = img.crop((left, top, right, bottom))

    # Resize the image to 150x150 pixels (adjust as needed)
    img.thumbnail((150, 150))

    img.save(picture_path)

    # Update user's profile image
    user.profile_image = picture_filename
    db.session.commit()

    return picture_filename


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()  # Create a new WTForms form for profile editing

    if form.validate_on_submit():
        if form.profile_image.data:
            picture_file = save_profile_picture(form.profile_image.data, current_user)
            print(f"Saved profile picture: {picture_file}")

        # Update user profile information based on form data
        if form.first_name.data:
            current_user.first_name = form.first_name.data
        if form.last_name.data:
            current_user.last_name = form.last_name.data

        new_email = form.email.data
        if new_email and new_email != current_user.email:
            # Check if the new email is already in use by another user
            existing_user = User.query.filter(db.func.lower(User.email) == db.func.lower(new_email)).first()
            if existing_user:
                flash('Email already in use. Please choose a different one.', 'danger')
                return redirect(url_for('profile'))

            current_user.email = new_email

        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            current_user.password = hashed_password

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except IntegrityError as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
        return redirect(url_for('profile'))

    # Populate the form with current user information
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.email.data = current_user.email
    # Add more fields as needed

    return render_template('profile.html', form=form)


@app.route('/chats')
@login_required
def chats():
    user_id = current_user.id

    private_chats = User.query.join(Conversation, or_(
        (Conversation.user1_id == user_id),
        (Conversation.user2_id == user_id)
    )).filter(
        ((Conversation.user1_id == user_id) & (User.id == Conversation.user2_id)) |
        ((Conversation.user2_id == user_id) & (User.id == Conversation.user1_id))
    ).all()

    joined_groups = current_user.groups_joined
    private_chats = [chat for chat in private_chats if chat.id != current_user.id]
    return render_template('chats.html', private_chats=private_chats, joined_groups=joined_groups)


@app.route('/private_chat/<recipient_username>', methods=['GET', 'POST'])
@login_required
def private_chat(recipient_username):
    # Get the recipient user by username
    recipient = User.query.filter_by(username=recipient_username).first()

    if request.method == 'POST':
        content = request.form.get('content')

        # Check if a conversation between the users already exists
        conversation = Conversation.query.filter(
            (Conversation.user1_id == current_user.id) & (Conversation.user2_id == recipient.id) |
            (Conversation.user2_id == current_user.id) & (Conversation.user1_id == recipient.id)
        ).first()

        if not conversation:
            # Create a new conversation if one doesn't exist
            conversation = Conversation(user1_id=current_user.id, user2_id=recipient.id)
            db.session.add(conversation)
            db.session.commit()

        # Create a new message
        new_message = Message(
            content=content,
            timestamp=datetime.utcnow(),
            user_id=current_user.id,
            conversation_id=conversation.id
        )

        db.session.add(new_message)
        db.session.commit()

        # Notify clients about the new private message
        socketio.emit('new_private_message', {
            'username': current_user.username,
            'content': content,
            'timestamp': str(datetime.utcnow()),
            'recipient_username': recipient_username
        }, room=f'private-{recipient_username}-{current_user.username}')

        return redirect(url_for('private_chat', recipient_username=recipient_username))

    # Query for private messages between the current user and the recipient
    private_messages = Message.query.filter(
        (Message.conversation.has(Conversation.user1_id == current_user.id)) |
        (Message.conversation.has(Conversation.user2_id == current_user.id)),
        (Message.conversation.has(Conversation.user1_id == recipient.id)) |
        (Message.conversation.has(Conversation.user2_id == recipient.id))
    ).order_by(Message.timestamp).all()

    private_messages_data = [
        {
            'id': message.id,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'current_username': message.user.username,
            'recipient_username': recipient.username,
            'recipient_first_name': recipient.first_name,
            'recipient_last_name': recipient.last_name
        }
        for message in private_messages
    ]
    # Render the private chat template
    return render_template('private_chat.html', form=MessageForm(), recipient=recipient, private_messages=private_messages_data)


@app.route('/delete_message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    message = Message.query.get(message_id)

    if message:
        if message.user == current_user:
            db.session.delete(message)
            db.session.commit()

            # Emit the 'deleted_message' event to notify clients
            socketio.emit('deleted_message', {'message_id': message_id}, room='chat')

            return jsonify({'message': 'Message deleted successfully'})
        else:
            return jsonify({'error': 'You are not authorized to delete this message'}), 403
    else:
        return jsonify({'error': 'Message not found'}), 404


@app.route('/contacts', methods=['GET', 'POST'])
@login_required
def add_contact():
    form = AddContactForm()

    if form.validate_on_submit():
        contact_username = form.username.data
        contact = User.query.filter_by(username=contact_username).first()

        if contact:
            # Check if the contact is already in the user's contacts
            if contact not in current_user.contacts:
                # Append the actual User instance, not the ID as a string
                current_user.contacts.append(contact)
                try:
                    db.session.commit()
                    flash(f'Contact {contact_username} added!', 'success')
                except IntegrityError:
                    db.session.rollback()
                    flash(f'Contact {contact_username} is already in your contacts.', 'warning')
            else:
                flash(f'Contact {contact_username} is already in your contacts.', 'warning')
        else:
            flash('User not found. Please enter a valid username.', 'danger')
        return redirect(url_for('add_contact'))

    return render_template('contacts.html', form=form)


@app.route('/delete_contact/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    contact = User.query.get(contact_id)

    if contact:
        if contact in current_user.contacts:
            current_user.contacts.remove(contact)
            db.session.commit()
            flash(f'Contact {contact.full_name} deleted!', 'success')
        else:
            flash('You can only delete contacts you have added.', 'danger')
    else:
        flash('Contact not found.', 'danger')

    return redirect(url_for('add_contact'))


# Route for creating or joining a group
@app.route('/groups', methods=['GET', 'POST'])
@login_required
def groups():
    create_form = CreateGroupForm()
    join_form = JoinGroupForm()

    if create_form.validate_on_submit():
        # Create a new group
        new_group = Group(name=create_form.name.data, admin=current_user)
        db.session.add(new_group)
        new_group.members.append(current_user)
        db.session.commit()
        flash('Group created successfully!', 'success')
        return redirect(url_for('groups'))

    if join_form.validate_on_submit():
        # Join an existing group
        group = Group.query.filter_by(name=join_form.group_name.data).first()

        if group:
            # Check if the user is already a member
            if current_user in group.members:
                flash('You are already a member of this group.', 'info')
            else:
                # Add the user to the group
                group.members.append(current_user)
                db.session.commit()
                flash('Joined the group successfully!', 'success')
        else:
            flash('Group not found. Please check the group name.', 'danger')

        return redirect(url_for('groups'))

    # Fetch user's created and joined groups
    created_groups = current_user.groups

    return render_template('groups.html', create_form=create_form, join_form=join_form,
                           created_groups=created_groups)


@app.route('/group/<int:group_id>')
@login_required
def group_profile(group_id):
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('chats'))

    # Fetch all group members
    group_members = GroupMember.query.filter_by(group_id=group_id).all()

    # Populate admin members list
    group.admin_members = [member.user_id for member in group_members if member.admin]

    return render_template('group_profile.html', group=group, group_members=group_members)


@app.route('/leave_group/<int:group_id>', methods=['POST'])
@login_required
def leave_group(group_id):
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('chats'))

    if current_user in group.members:
        group.members.remove(current_user)
        db.session.commit()
        flash('You have left the group successfully!', 'success')
    else:
        flash('You are not a member of this group!', 'danger')

    return redirect(url_for('chats'))


@app.route('/promote_admin/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def promote_admin(group_id, user_id):
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('index'))

    # Check if the current user is the owner of the group
    group_member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not group_member or current_user.id != group.owner_id:
        flash('You are not authorized to perform this action!', 'danger')
        return redirect(url_for('group_profile', group_id=group_id))

    # Find the group member to promote
    group_member_to_promote = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if group_member_to_promote:
        group_member_to_promote.admin = True
        db.session.commit()
        flash('User promoted to admin!', 'success')
    else:
        flash('User not found in group!', 'danger')

    return redirect(url_for('group_profile', group_id=group_id))


@app.route('/revoke_admin/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def revoke_admin(group_id, user_id):
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('index'))

    # Check if the current user is the owner of the group
    group_member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not group_member or current_user.id != group.owner_id:
        flash('You are not authorized to perform this action!', 'danger')
        return redirect(url_for('group_profile', group_id=group_id))

    # Find the group member to revoke admin status
    group_member_to_revoke = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if group_member_to_revoke:
        group_member_to_revoke.admin = False
        db.session.commit()
        flash('Admin status revoked for the user!', 'success')
    else:
        flash('User not found in group!', 'danger')

    return redirect(url_for('group_profile', group_id=group_id))


@app.route('/remove_member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member(group_id, user_id):
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found!', 'danger')
        return redirect(url_for('index'))

    # Check if the current user is the owner of the group or an admin
    group_member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not group_member or (current_user.id != group.owner_id and not group_member.admin):
        flash('You are not authorized to perform this action!', 'danger')
        return redirect(url_for('group_profile', group_id=group_id))

    # Find the group member to remove
    group_member_to_remove = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if group_member_to_remove:
        db.session.delete(group_member_to_remove)
        db.session.commit()
        flash('User removed from the group!', 'success')
    else:
        flash('User not found in group!', 'danger')

    return redirect(url_for('group_profile', group_id=group_id))


@app.route('/delete_group/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    # Retrieve the group from the database based on the provided group_id
    group = Group.query.get(group_id)

    # Check if the group exists
    if group:
        # Perform deletion logic
        db.session.delete(group)
        db.session.commit()
        return redirect(url_for('groups'))  # Redirect to the groups page or any other appropriate page
    else:
        return 'Group {} not found.'.format(group_id)


@app.route('/group_chat/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)

    if current_user not in group.members:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('groups'))

    # Get existing group messages
    group_messages = Message.query.filter_by(group_id=group.id).all()
    group_messages_as_dict = [message.as_dict() for message in group_messages]

    if request.method == 'POST':
        print("Received a POST request")
        content = request.form.get('content')
        sender_username = current_user.username
        timestamp = datetime.utcnow()

        print(f"Received message: {content}")

        # Create a new message
        message = Message(
            content=content,
            group_id=group.id,
            user_id=current_user.id,
            timestamp=timestamp
        )

        db.session.add(message)
        db.session.commit()

        print(f"Saved message to database: {message}")

        # Broadcast the new group message to all connected clients
        socketio.emit('new_group_message', {
            'id': message.id,
            'content': message.content,
            'group_id': group.id,
            'current_username': sender_username,
            'timestamp': timestamp.isoformat()
        }, room=f'group_{group.id}')
        return redirect(url_for('group_chat', group_id=group_id))

    return render_template('group_chat.html', group=group, form=MessageForm(), group_messages=group_messages_as_dict)


@app.route('/meeting/<room_name>', methods=['GET', 'POST'])
@login_required
def meeting(room_name):
    jaasJwt = JaaSJwtBuilder()

    token = jaasJwt.withDefaults() \
        .withApiKey("vpaas-magic-cookie-287f77db606949a6826748ddc7cf4d04/63cc98") \
        .withUserName(current_user.first_name + " " + current_user.last_name) \
        .withUserEmail(current_user.email) \
        .withModerator(True) \
        .withAppID("vpaas-magic-cookie-287f77db606949a6826748ddc7cf4d04") \
        .withUserAvatar(file_dir + "\\static\\profile_pics\\" + current_user.profile_image) \
        .signWith("""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCI+iSs7bFHhLXl
HNx0eF1O4hWMPMEfY+rY9a/rG9z3eV82w4PU0VeRpXCbjwKVcWgML5PAMYkdIr8o
cFeC5RCEPV6fxW9wj1vh7vrW5dpuriERqxLnh3Fq6pEHUHUEDu26+tc7Kx2GAC3H
bkPJ6djOl6LwQGxnKdbREXDIGbTBX+WzYiP8SWWTLIOkj7hmM47TY4QbUrE07QQW
9T3gHs8Uq5qXn8wSHitb0or/aJnnK0WxuNja80Xak2XWA5WCaDeboxicvSYXqIRo
VpwQfluepYusnUJGGUgnxaOr3dNhtpRFe45jDoOeoEzoxROeDhXO2HmnbnvLnX3n
cTQDPpq3AgMBAAECggEAX6RJd3WAEy/W0eMVCz3/6NRztze0oPZjRJpH+yG5aBKX
KOXbZv3E5y1dM0DnzPEidV/DCq+LzYw1bUcD06GdprgzGdwBs9ZlkZwMCYD0w9NR
w8Rvrrojt0ORgEntaqgB1kzPe8DfHHGDhXy4WIOvnpDCdH6HMoFEPTawSQep7lrB
S+RLbZxBNtKrx4XY+k4ZPTkFYfGjFHYPwAIrg9HN9U27IheMpPNBikOfOOtS74rh
w5X6O8MnFpAXvmvTI/uDftsi5ZBIQKOo2lKIG31nMeStjgswtLy8welmlf4gCKfD
ciGm9ZfhGZ+v2J4JMKMEo1lXe9VV2DlxGYNR+1D6AQKBgQDG9p+7hmx3iVFIgT8g
ayiBE/H15xfaEQr82EtnlUL/uJQ6p2jLK3Y5/KRq3m4lT6PFKlmvmXRhOfo2CojO
Z6B4H0mMTlTmOcch5gQkICcFac0Rlnj3MguUG7l7OfH3J8BDTCl+xXMgmiJgAeiJ
ktOKXBZNnK1dr9lewFbbkKWe4wKBgQCwPoSxwkMRYL/ThGyyeZJIwuv9wyOKIIUX
xS/b/NILHOvH3GsEJJkMPSMm83Kw82EYQfUxZD2I0yGzHXOEx0ZGJBmgtfP80XYZ
HyubfE4DO/Cl14ZnXTKpq+D3ZYri/cR7E/dWBRZtH7Lc1T1hJR5RxJUWcOdURqVH
JbxLkNXpHQKBgQCINuh8tjckT3q6rOHPDA4a8NDCjYgi33AqUtqs+992u6Of1GVG
U2cJpBHcqJO4L6HrpmbodaLbvZmzzdqDlSajlqf/ytENHZlbd+J16R1N83VWCTKf
6j9LEwAVgUJK94gFiusNw5hiRaQrHqNZLJBvNUR/tjhq361t1Tih8ZGyCQKBgBdc
ghxJ4rf3+hVgdUQHB1PrunpNlnVlsB6hfaGMVo8wizRXzDulWkAcDn/IP0ijShh8
DbM5VUrAqbPjUH+mJnN/r4H0/F1jqmLUFeSrSm/1TwW8ls02tlN1PAGvDQTfnF6w
G9XkIL/gNsY84cDxuZ4fD6AE4TTzlE7k+puNnD0lAoGBAJrZOneMhRRT0V+47cQ/
BHyFbUcAUIu/upW9QUGe9uhlCPl5e91MVhcRECqYOzHE0OkFRl3t8lFtoX9+PiEM
cXbevrLfjwVzOIkZHn1CRJ3mNcQZL/te64A9Dff68SkUsQqwj8ijIN1fd+zEqKZs
UrCF3GJUGKuGwB265BXD0LhO
-----END PRIVATE KEY-----""")

    return render_template('meeting.html', token=str(token)[2:-1], room_name=room_name)


@app.route('/start_meeting', methods=['GET', 'POST'])
@login_required
def start_meeting():
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        #session['room_name'] = room_name
        return redirect(url_for('meeting',room_name=room_name))

    # Render the start_meeting.html template for GET requests
    return render_template('start_meeting.html')


@app.errorhandler(404)
def showError(error):
    return render_template('error_404.html') , 404