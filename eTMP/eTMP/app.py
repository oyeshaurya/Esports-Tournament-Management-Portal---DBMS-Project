from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Identity, AnonymousIdentity, identity_changed, identity_loaded, RoleNeed, UserNeed, Permission
from datetime import datetime, timedelta
import uuid
import os
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Generate a secure random secret key

# Database Configuration (Update as per your MySQL credentials)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:SQLpass1@localhost/esports_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize Flask-Principal
principals = Principal(app)

# Define roles
admin_permission = Permission(RoleNeed('admin'))
player_permission = Permission(RoleNeed('player'))
manager_permission = Permission(RoleNeed('manager'))

# -------------------- MODELS --------------------

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'player', 'manager'
    
    # Extended fields
    date_of_birth = db.Column(db.Date, nullable=True)
    country = db.Column(db.String(100), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    team_memberships = db.relationship('TeamMember', back_populates='user', lazy='dynamic')
    managed_teams = db.relationship('Team', back_populates='manager', lazy='dynamic')
    performances = db.relationship('PlayerPerformance', back_populates='user', lazy='dynamic')

    def get_id(self):
        return str(self.user_id)

class Team(db.Model):
    __tablename__ = 'teams'
    
    team_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    manager_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    
    # Extended fields
    logo_url = db.Column(db.String(255), nullable=True)
    founded_date = db.Column(db.Date, nullable=True)
    team_description = db.Column(db.Text, nullable=True)
    region = db.Column(db.String(100), nullable=True)
    
    # Relationships
    manager = db.relationship('User', back_populates='managed_teams')
    members = db.relationship('TeamMember', back_populates='team', lazy='dynamic')
    tournament_registrations = db.relationship('TournamentRegistration', back_populates='team', lazy='dynamic')
    match_scores = db.relationship('MatchScore', back_populates='team', lazy='dynamic')
    performances = db.relationship('PlayerPerformance', back_populates='team', lazy='dynamic')
    tournament_standings = db.relationship('TournamentStanding', back_populates='team', lazy='dynamic')

class TeamMember(db.Model):
    __tablename__ = 'team_members'
    
    member_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Extended fields
    role = db.Column(db.String(50), nullable=True)  # e.g., Captain, Player, Substitute
    in_game_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.Enum('Active', 'Inactive', 'Suspended'), default='Active')
    
    # Relationships
    user = db.relationship('User', back_populates='team_memberships')
    team = db.relationship('Team', back_populates='members')

class Tournament(db.Model):
    __tablename__ = 'tournaments'
    
    tournament_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    game = db.Column(db.String(50), nullable=False)
    max_teams = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='upcoming')  # upcoming, ongoing, completed
    
    # Extended fields
    prize_pool = db.Column(db.Numeric(10,2), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    tournament_type = db.Column(db.Enum('Online', 'LAN', 'Hybrid'), default='Online')
    creator_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)  # Add creator field
    
    # Relationships
    registrations = db.relationship('TournamentRegistration', back_populates='tournament', lazy='dynamic')
    matches = db.relationship('Match', back_populates='tournament', lazy='dynamic')
    standings = db.relationship('TournamentStanding', back_populates='tournament', lazy='dynamic')
    game_statistics = db.relationship('GameStatistic', back_populates='tournament', lazy='dynamic')
    creator = db.relationship('User')

class TournamentRegistration(db.Model):
    __tablename__ = 'tournament_registrations'
    
    registration_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournaments.tournament_id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    registration_status = db.Column(db.Enum('Pending', 'Approved', 'Rejected'), default='Pending')
    
    # Relationships
    tournament = db.relationship('Tournament', back_populates='registrations')
    team = db.relationship('Team', back_populates='tournament_registrations')

class Match(db.Model):
    __tablename__ = 'matches'
    
    match_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournaments.tournament_id'), nullable=False)
    round_number = db.Column(db.Integer)
    team1_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    team2_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    match_date = db.Column(db.DateTime, nullable=False)
    venue = db.Column(db.String(100))
    match_type = db.Column(db.Enum('Group', 'Knockout', 'Final'), default='Group')
    status = db.Column(db.String(20), default='scheduled')  # scheduled, ongoing, completed
    winner_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=True)
    
    # Relationships
    tournament = db.relationship('Tournament', back_populates='matches')
    team1 = db.relationship('Team', foreign_keys=[team1_id])
    team2 = db.relationship('Team', foreign_keys=[team2_id])
    winner = db.relationship('Team', foreign_keys=[winner_id])
    scores = db.relationship('MatchScore', back_populates='match')
    performances = db.relationship('PlayerPerformance', back_populates='match')

class MatchScore(db.Model):
    __tablename__ = 'match_scores'
    
    score_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    match_id = db.Column(db.Integer, db.ForeignKey('matches.match_id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    
    score = db.Column(db.Integer, nullable=False)
    map_name = db.Column(db.String(100))
    kills = db.Column(db.Integer)
    deaths = db.Column(db.Integer)
    assists = db.Column(db.Integer)
    objective_points = db.Column(db.Integer)
    round_wins = db.Column(db.Integer)
    
    # Relationships
    match = db.relationship('Match', back_populates='scores')
    team = db.relationship('Team', back_populates='match_scores')

class PlayerPerformance(db.Model):
    __tablename__ = 'player_performances'
    
    performance_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    match_id = db.Column(db.Integer, db.ForeignKey('matches.match_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    
    kills = db.Column(db.Integer, default=0)
    deaths = db.Column(db.Integer, default=0)
    assists = db.Column(db.Integer, default=0)
    headshots = db.Column(db.Integer, default=0)
    accuracy = db.Column(db.Float)
    damage_dealt = db.Column(db.Integer, default=0)
    healing_done = db.Column(db.Integer, default=0)
    time_played = db.Column(db.Integer)  # in seconds
    
    # Relationships
    match = db.relationship('Match', back_populates='performances')
    user = db.relationship('User', back_populates='performances')
    team = db.relationship('Team', back_populates='performances')

class TournamentStanding(db.Model):
    __tablename__ = 'tournament_standings'
    
    standing_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournaments.tournament_id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.team_id'), nullable=False)
    
    final_rank = db.Column(db.Integer)
    points = db.Column(db.Integer, default=0)
    matches_played = db.Column(db.Integer, default=0)
    matches_won = db.Column(db.Integer, default=0)
    matches_lost = db.Column(db.Integer, default=0)
    
    # Relationships
    tournament = db.relationship('Tournament', back_populates='standings')
    team = db.relationship('Team', back_populates='tournament_standings')

class GameStatistic(db.Model):
    __tablename__ = 'game_statistics'
    
    statistic_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournaments.tournament_id'), nullable=False)
    
    total_matches = db.Column(db.Integer, default=0)
    total_teams = db.Column(db.Integer, default=0)
    total_players = db.Column(db.Integer, default=0)
    average_match_duration = db.Column(db.Integer)  # in minutes
    most_picked_character = db.Column(db.String(100))
    most_banned_character = db.Column(db.String(100))
    
    # Relationships
    tournament = db.relationship('Tournament', back_populates='game_statistics')

# -------------------- HELPER FUNCTIONS --------------------

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        return f"/static/uploads/{unique_filename}"
    return None

# -------------------- AUTHENTICATION --------------------

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Setup roles when a user logs in
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'user_id'):
        identity.provides.add(UserNeed(current_user.user_id))

    # Assuming the User model has a role attribute
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            
            # Tell Flask-Principal the identity changed
            identity_changed.send(app, identity=Identity(user.user_id))
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        
        # Check if role is valid
        if role not in ['admin', 'player', 'manager']:
            flash('Invalid role selection', 'danger')
            return redirect(url_for('register'))
            
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
            
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            role=role
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    
    # Tell Flask-Principal the user is anonymous
    identity_changed.send(app, identity=AnonymousIdentity())
    
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# -------------------- DASHBOARD ROUTES --------------------

@app.route('/dashboard')
@login_required
def dashboard():
    # Route to appropriate dashboard based on role
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    elif current_user.role == 'player':
        return redirect(url_for('player_dashboard'))
    else:
        flash('Invalid user role', 'danger')
        return redirect(url_for('logout'))

@app.route('/dashboard/player')
@login_required
@player_permission.require(http_exception=403)
def player_dashboard():
    # Get teams the player is a member of
    team_memberships = current_user.team_memberships.all()
    
    # Get tournaments the player's teams are registered for
    tournaments = []
    team_ids = [membership.team_id for membership in team_memberships]
    
    for team_id in team_ids:
        team_tournaments = TournamentRegistration.query.filter_by(team_id=team_id).all()
        for registration in team_tournaments:
            if registration.tournament not in tournaments:
                tournaments.append(registration.tournament)
    
    # Get upcoming matches for the player's teams
    upcoming_matches = Match.query.filter(
        (Match.team1_id.in_(team_ids) | Match.team2_id.in_(team_ids)) &
        (Match.status == 'scheduled') &
        (Match.match_date > datetime.now())
    ).order_by(Match.match_date).all()
    
    return render_template('player_dashboard.html', 
                            user=current_user,
                            team_memberships=team_memberships,
                            tournaments=tournaments,
                            upcoming_matches=upcoming_matches)

@app.route('/dashboard/manager')
@login_required
@manager_permission.require(http_exception=403)
def manager_dashboard():
    # Get tournaments created by this manager
    tournaments = Tournament.query.filter_by(creator_id=current_user.user_id).all()
    
    # Get teams managed by this manager
    teams = Team.query.filter_by(manager_id=current_user.user_id).all()
    
    # Get upcoming matches in those tournaments
    tournament_ids = [tournament.tournament_id for tournament in tournaments]
    upcoming_matches = Match.query.filter(
        Match.tournament_id.in_(tournament_ids),
        Match.status == 'scheduled',
        Match.match_date > datetime.now()
    ).order_by(Match.match_date).all()
    
    return render_template('manager_dashboard.html',
                            user=current_user,
                            tournaments=tournaments,
                            teams=teams,
                            upcoming_matches=upcoming_matches)

@app.route('/dashboard/admin')
@login_required
@admin_permission.require(http_exception=403)
def admin_dashboard():
    # Get counts for dashboard
    users_count = User.query.count()
    tournaments_count = Tournament.query.count()
    teams_count = Team.query.count()
    matches_count = Match.query.count()
    
    # Get latest users, tournaments, and matches
    latest_users = User.query.order_by(User.registration_date.desc()).limit(5).all()
    latest_tournaments = Tournament.query.order_by(Tournament.start_date.desc()).limit(5).all()
    upcoming_matches = Match.query.filter(
        Match.status == 'scheduled',
        Match.match_date > datetime.now()
    ).order_by(Match.match_date).limit(5).all()
    
    return render_template('admin_dashboard.html',
                            users_count=users_count,
                            tournaments_count=tournaments_count,
                            teams_count=teams_count,
                            matches_count=matches_count,
                            latest_users=latest_users,
                            latest_tournaments=latest_tournaments,
                            upcoming_matches=upcoming_matches)

# -------------------- USER SETTINGS ROUTES --------------------

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if request.method == 'POST':
        # Update user profile
        current_user.name = request.form['name']
        current_user.email = request.form['email']
        
        # Check if email already exists
        if User.query.filter(User.email == current_user.email, User.user_id != current_user.user_id).first():
            flash('Email already in use', 'danger')
            return redirect(url_for('user_profile'))
            
        # Update other fields
        if 'date_of_birth' in request.form and request.form['date_of_birth']:
            current_user.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')
        
        if 'country' in request.form:
            current_user.country = request.form['country']
            
        if 'contact_number' in request.form:
            current_user.contact_number = request.form['contact_number']
        
        # Handle profile picture upload
        if 'profile_picture' in request.files and request.files['profile_picture'].filename:
            file = request.files['profile_picture']
            file_path = save_file(file)
            if file_path:
                current_user.profile_picture = file_path
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))
    
    return render_template('user_profile.html', user=current_user)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if current password is correct
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))
            
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
            
        # Update password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('user_profile'))
    
    return render_template('change_password.html')

# -------------------- PLAYER ROUTES --------------------

@app.route('/player/team/<int:team_id>')
@login_required
@player_permission.require(http_exception=403)
def player_team_view(team_id):
    # Check if player is actually in this team
    team_member = TeamMember.query.filter_by(user_id=current_user.user_id, team_id=team_id).first()
    if not team_member:
        flash('You are not a member of this team', 'danger')
        return redirect(url_for('player_dashboard'))
    
    team = Team.query.get_or_404(team_id)
    team_members = team.members.all()
    
    # Get tournaments this team is registered for
    tournaments = [reg.tournament for reg in team.tournament_registrations]
    
    # Get upcoming matches for this team
    upcoming_matches = Match.query.filter(
        (Match.team1_id == team_id) | (Match.team2_id == team_id),
        Match.status == 'scheduled',
        Match.match_date > datetime.now()
    ).order_by(Match.match_date).all()
    
    return render_template('player_team_view.html',
                            team=team,
                            team_members=team_members,
                            tournaments=tournaments,
                            upcoming_matches=upcoming_matches)

@app.route('/player/tournament/<int:tournament_id>')
@login_required
@player_permission.require(http_exception=403)
def player_tournament_view(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if player's team is registered in this tournament
    team_ids = [team_member.team_id for team_member in current_user.team_memberships]
    registrations = TournamentRegistration.query.filter(
        TournamentRegistration.tournament_id == tournament_id,
        TournamentRegistration.team_id.in_(team_ids)
    ).all()
    
    if not registrations:
        flash('Your team is not registered for this tournament', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Get all matches in this tournament
    matches = tournament.matches.order_by(Match.match_date).all()
    
    # Get team standings
    standings = tournament.standings.all()
    
    return render_template('player_tournament_view.html',
                            tournament=tournament,
                            matches=matches,
                            standings=standings)

@app.route('/player/match/<int:match_id>')
@login_required
@player_permission.require(http_exception=403)
def player_match_view(match_id):
    match = Match.query.get_or_404(match_id)
    
    # Check if player's team is in this match
    team_ids = [team_member.team_id for team_member in current_user.team_memberships]
    if match.team1_id not in team_ids and match.team2_id not in team_ids:
        flash('Your team is not participating in this match', 'danger')
        return redirect(url_for('player_dashboard'))
    
    # Get match scores
    scores = match.scores
    
    # Get player performances
    performances = match.performances
    
    return render_template('player_match_view.html',
                            match=match,
                            scores=scores,
                            performances=performances)

# -------------------- MANAGER ROUTES --------------------

@app.route('/manager/tournaments')
@login_required
@manager_permission.require(http_exception=403)
def manager_tournaments():
    # Get tournaments created by this manager
    tournaments = Tournament.query.filter_by(creator_id=current_user.user_id).all()
    return render_template('manager_tournaments.html', tournaments=tournaments)

@app.route('/manager/tournaments/<int:tournament_id>/matches')
@login_required
@manager_permission.require(http_exception=403)
def tournament_matches(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only view matches for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get matches for this tournament
    matches = tournament.matches.order_by(Match.match_date).all()
    
    return render_template('tournament_matches.html', tournament=tournament, matches=matches)

@app.route('/manager/tournaments/create', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def create_tournament():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%dT%H:%M')
        game = request.form['game']
        max_teams = int(request.form['max_teams'])
        location = request.form['location']
        tournament_type = request.form['tournament_type']
        prize_pool = float(request.form['prize_pool']) if request.form['prize_pool'] else None
        
        # Validate the dates
        if start_date >= end_date:
            flash('End date must be after start date', 'danger')
            return redirect(url_for('create_tournament'))
        
        # Create the tournament
        new_tournament = Tournament(
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            game=game,
            max_teams=max_teams,
            location=location,
            tournament_type=tournament_type,
            prize_pool=prize_pool,
            creator_id=current_user.user_id
        )
        
        db.session.add(new_tournament)
        db.session.commit()
        
        flash('Tournament created successfully!', 'success')
        return redirect(url_for('manager_tournaments'))
    
    return render_template('create_tournament.html')

@app.route('/manager/tournaments/<int:tournament_id>/edit', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def edit_tournament(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only edit tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    if request.method == 'POST':
        tournament.name = request.form['name']
        tournament.description = request.form['description']
        tournament.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M')
        tournament.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%dT%H:%M')
        tournament.game = request.form['game']
        tournament.max_teams = int(request.form['max_teams'])
        tournament.location = request.form['location']
        tournament.tournament_type = request.form['tournament_type']
        tournament.prize_pool = float(request.form['prize_pool']) if request.form['prize_pool'] else None
        
        db.session.commit()
        
        flash('Tournament updated successfully!', 'success')
        return redirect(url_for('manager_tournaments'))
    
    return render_template('edit_tournament.html', tournament=tournament)

# Completing the delete_tournament function
@app.route('/manager/tournaments/<int:tournament_id>/delete', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def delete_tournament(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only delete tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Delete related records first to avoid foreign key constraints
    # Delete standings
    TournamentStanding.query.filter_by(tournament_id=tournament_id).delete()
    
    # Delete game statistics
    GameStatistic.query.filter_by(tournament_id=tournament_id).delete()
    
    # Get all matches in this tournament
    matches = Match.query.filter_by(tournament_id=tournament_id).all()
    for match in matches:
        # Delete match scores
        MatchScore.query.filter_by(match_id=match.match_id).delete()
        # Delete player performances
        PlayerPerformance.query.filter_by(match_id=match.match_id).delete()
    
    # Delete matches
    Match.query.filter_by(tournament_id=tournament_id).delete()
    
    # Delete registrations
    TournamentRegistration.query.filter_by(tournament_id=tournament_id).delete()
    
    # Finally, delete the tournament
    db.session.delete(tournament)
    db.session.commit()
    
    flash('Tournament deleted successfully!', 'success')
    return redirect(url_for('manager_tournaments'))

@app.route('/manager/tournaments/<int:tournament_id>')
@login_required
@manager_permission.require(http_exception=403)
def view_tournament(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only view tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get registrations for this tournament
    registrations = tournament.registrations.all()
    
    # Get matches for this tournament
    matches = tournament.matches.order_by(Match.match_date).all()
    
    return render_template('view_tournament.html', 
                          tournament=tournament, 
                          registrations=registrations, 
                          matches=matches)

# -------------------- TEAM MANAGEMENT ROUTES --------------------

@app.route('/manager/teams')
@login_required
@manager_permission.require(http_exception=403)
def manager_teams():
    # Get teams managed by this manager
    teams = Team.query.filter_by(manager_id=current_user.user_id).all()
    return render_template('manager_teams.html', teams=teams)

@app.route('/manager/teams/create', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def create_team():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['team_description']
        region = request.form['region']
        
        # Check if team name already exists
        if Team.query.filter_by(name=name).first():
            flash('Team name already exists', 'danger')
            return redirect(url_for('create_team'))
        
        # Handle logo upload
        logo_url = None
        if 'logo' in request.files and request.files['logo'].filename:
            file = request.files['logo']
            logo_url = save_file(file)
        
        # Create new team
        new_team = Team(
            name=name,
            manager_id=current_user.user_id,
            logo_url=logo_url,
            founded_date=datetime.now().date(),
            team_description=description,
            region=region
        )
        
        db.session.add(new_team)
        db.session.commit()
        
        flash('Team created successfully!', 'success')
        return redirect(url_for('manager_teams'))
    
    return render_template('create_team.html')

@app.route('/manager/teams/<int:team_id>/edit', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def edit_team(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Check if this manager manages this team
    if team.manager_id != current_user.user_id:
        flash('You can only edit teams you manage', 'danger')
        return redirect(url_for('manager_teams'))
    
    if request.method == 'POST':
        team.name = request.form['name']
        team.team_description = request.form['team_description']
        team.region = request.form['region']
        
        # Handle logo upload
        if 'logo' in request.files and request.files['logo'].filename:
            file = request.files['logo']
            logo_url = save_file(file)
            if logo_url:
                team.logo_url = logo_url
        
        db.session.commit()
        
        flash('Team updated successfully!', 'success')
        return redirect(url_for('manager_teams'))
    
    return render_template('edit_team.html', team=team)

@app.route('/manager/teams/<int:team_id>/delete', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def delete_team(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Check if this manager manages this team
    if team.manager_id != current_user.user_id:
        flash('You can only delete teams you manage', 'danger')
        return redirect(url_for('manager_teams'))
    
    # Check if team is registered in any tournaments
    if team.tournament_registrations.count() > 0:
        flash('Cannot delete team that is registered in tournaments', 'danger')
        return redirect(url_for('manager_teams'))
    
    # Delete team members first
    TeamMember.query.filter_by(team_id=team_id).delete()
    
    # Delete the team
    db.session.delete(team)
    db.session.commit()
    
    flash('Team deleted successfully!', 'success')
    return redirect(url_for('manager_teams'))

@app.route('/manager/teams/<int:team_id>')
@login_required
@manager_permission.require(http_exception=403)
def view_team(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Check if this manager manages this team
    if team.manager_id != current_user.user_id:
        flash('You can only view teams you manage', 'danger')
        return redirect(url_for('manager_teams'))
    
    # Get team members
    team_members = team.members.all()
    
    return render_template('view_team.html', team=team, team_members=team_members)

@app.route('/manager/teams/<int:team_id>/add-member', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def add_team_member(team_id):
    team = Team.query.get_or_404(team_id)
    
    # Check if this manager manages this team
    if team.manager_id != current_user.user_id:
        flash('You can only add members to teams you manage', 'danger')
        return redirect(url_for('manager_teams'))
    
    if request.method == 'POST':
        email = request.form['email']
        role = request.form['role']
        in_game_name = request.form['in_game_name']
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User  not found with this email', 'danger')
            return redirect(url_for('add_team_member', team_id=team_id))
        
        # Check if user is already in team
        existing_membership = TeamMember.query.filter_by(user_id=user.user_id, team_id=team_id).first()
        if existing_membership:
            flash('User  is already a member of this team', 'danger')
            return redirect(url_for('add_team_member', team_id=team_id))
        
        # Add user to team
        new_member = TeamMember(
            user_id=user.user_id,
            team_id=team_id,
            role=role,
            in_game_name=in_game_name,
            status='Active'
        )
        
        db.session.add(new_member)
        db.session.commit()
        
        flash('Team member added successfully!', 'success')
        return redirect(url_for('view_team', team_id=team_id))
    
    return render_template('add_team_member.html', team=team)

@app.route('/manager/teams/<int:team_id>/remove-member/<int:member_id>', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def remove_team_member(team_id, member_id):
    team = Team.query.get_or_404(team_id)
    
    # Check if this manager manages this team
    if team.manager_id != current_user.user_id:
        flash('You can only remove members from teams you manage', 'danger')
        return redirect(url_for('manager_teams'))
    
    # Find team member
    member = TeamMember.query.get_or_404(member_id)
    if member.team_id != team_id:
        flash('Member not found in this team', 'danger')
        return redirect(url_for('view_team', team_id=team_id))
    
    # Remove member
    db.session.delete(member)
    db.session.commit()
    
    flash('Team member removed successfully!', 'success')
    return redirect(url_for('view_team', team_id=team_id))

# -------------------- MATCH MANAGEMENT ROUTES --------------------

@app.route('/manager/tournaments/<int:tournament_id>/matches/details')
@login_required
@manager_permission.require(http_exception=403)
def tournament_match_details():
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only view matches for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get matches for this tournament
    matches = tournament.matches.order_by(Match.match_date).all()
    
    return render_template('tournament_matches.html', tournament=tournament, matches=matches)

@app.route('/manager/tournaments/<int:tournament_id>/matches/create', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def create_match(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only create matches for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get teams registered for this tournament
    registrations = tournament.registrations.filter_by(registration_status='Approved').all()
    teams = [registration.team for registration in registrations]
    
    if len(teams) < 2:
        flash('Need at least 2 teams registered before creating matches', 'danger')
        return redirect(url_for('tournament_matches', tournament_id=tournament_id))
    
    if request.method == 'POST':
        team1_id = int(request.form['team1_id'])
        team2_id = int(request.form['team2_id'])
        match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        venue = request.form['venue']
        match_type = request.form['match_type']
        round_number = int(request.form['round_number'])
        
        # Validate teams are different
        if team1_id == team2_id:
            flash('Teams must be different', 'danger')
            return redirect(url_for('create_match', tournament_id=tournament_id))
        
        # Create match
        new_match = Match(
            tournament_id=tournament_id,
            team1_id=team1_id,
            team2_id=team2_id,
            match_date=match_date,
            venue=venue,
            match_type=match_type,
            round_number=round_number,
            status='scheduled'
        )
        
        db.session.add(new_match)
        db.session.commit()
        
        flash('Match created successfully!', 'success')
        return redirect(url_for('tournament_matches', tournament_id=tournament_id))
    
    return render_template('create_match.html', tournament=tournament, teams=teams)

@app.route('/manager/matches/<int:match_id>/edit', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def edit_match(match_id):
    match = Match.query.get_or_404(match_id)
    tournament = Tournament.query.get_or_404(match.tournament_id)
    
    # Check if this manager created this match's tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only edit matches for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get teams registered for this tournament
    registrations = tournament.registrations.filter_by(registration_status='Approved').all()
    teams = [registration.team for registration in registrations]
    
    if request.method == 'POST':
        match.team1_id = int(request.form['team1_id'])
        match.team2_id = int(request.form['team2_id'])
        match.match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        match.venue = request.form['venue']
        match.match_type = request.form['match_type']
        match.round_number = int(request.form['round_number'])
        match.status = request.form['status']
        
        # If match is completed, update winner
        if match.status == 'completed' and 'winner_id' in request.form:
            match.winner_id = int(request.form['winner_id'])
        
        db.session.commit()
        
        flash('Match updated successfully!', 'success')
        return redirect(url_for('tournament_matches', tournament_id=tournament.tournament_id))
    
    return render_template('edit_match.html', match=match, tournament=tournament, teams=teams)

@app.route('/manager/matches/<int:match_id>/delete', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def delete_match(match_id):
    match = Match.query.get_or_404(match_id)
    tournament = Tournament.query.get_or_404(match.tournament_id)
    
    # Check if this manager created this match's tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only delete matches for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Delete match scores
    MatchScore.query.filter_by(match_id=match_id).delete()
    
    # Delete player performances
    PlayerPerformance.query.filter_by(match_id=match_id).delete()
    
    # Delete match
    db.session.delete(match)
    db.session.commit()
    
    flash('Match deleted successfully!', 'success')
    return redirect(url_for('tournament_matches', tournament_id=tournament.tournament_id))

@app.route('/manager/tournaments/<int:tournament_id>/register-team', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def register_team_for_tournament(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only register teams for tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Get teams managed by this manager
    teams = Team.query.filter_by(manager_id=current_user.user_id).all()
    
    # Filter out teams already registered
    registered_team_ids = [reg.team_id for reg in tournament.registrations]
    available_teams = [team for team in teams if team.team_id not in registered_team_ids]
    
    if request.method == 'POST':
        team_id = int(request.form['team_id'])
        
        # Check if team exists and is managed by this manager
        team = Team.query.get_or_404(team_id)
        if team.manager_id != current_user.user_id:
            flash('You can only register teams you manage', 'danger')
            return redirect(url_for('register_team_for_tournament', tournament_id=tournament_id))
        
        # Check if team is already registered
        existing_reg = TournamentRegistration.query.filter_by(
            tournament_id=tournament_id, 
            team_id=team_id
        ).first()
        
        if existing_reg:
            flash('Team is already registered for this tournament', 'danger')
            return redirect(url_for('view_tournament', tournament_id=tournament_id))
        
        # Register team
        new_registration = TournamentRegistration(
            tournament_id=tournament_id,
            team_id=team_id,
            registration_status='Approved'  # Auto-approve since manager is creating it
        )
        
        db.session.add(new_registration)
        db.session.commit()
        
        flash('Team registered successfully!', 'success')
        return redirect(url_for('view_tournament', tournament_id=tournament_id))
    
    return render_template('register_team.html', tournament=tournament, teams=available_teams)

@app.route('/manager/tournaments/<int:tournament_id>/remove-team/<int:team_id>', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def remove_team_from_tournament(tournament_id, team_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    # Check if this manager created this tournament
    if tournament.creator_id != current_user.user_id:
        flash('You can only remove teams from tournaments you created', 'danger')
        return redirect(url_for('manager_tournaments'))
    
    # Find registration
    registration = TournamentRegistration.query.filter_by(
        tournament_id=tournament_id, 
        team_id=team_id
    ).first_or_404()
    
    # Check if team is in any matches
    matches = Match.query.filter(
        Match.tournament_id == tournament_id,
        (Match.team1_id == team_id) | (Match.team2_id == team_id)
    ).all()
    
    if matches:
        flash('Cannot remove team that is in scheduled/played matches', 'danger')
        return redirect(url_for('view_tournament', tournament_id=tournament_id))
    
    # Remove registration
    db.session.delete(registration)
    db.session.commit()
    
    flash('Team removed from tournament successfully!', 'success')
    return redirect(url_for('view_tournament', tournament_id=tournament_id))

# -------------------- ADMIN ROUTES --------------------

@app.route('/admin/users')
@login_required
@admin_permission.require(http_exception=403)
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.role = request.form['role']
        
        if 'date_of_birth' in request.form and request.form['date_of_birth']:
            user.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')
            
        if 'country' in request.form:
            user.country = request.form['country']
            
        if 'contact_number' in request.form:
            user.contact_number = request.form['contact_number']
        
        if 'profile_picture' in request.files and request.files['profile_picture'].filename:
            file = request.files['profile_picture']
            file_path = save_file(file)
            if file_path:
                user.profile_picture = file_path
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin_delete_user(user_id):
    if user_id == current_user.user_id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    # Delete team memberships
    TeamMember.query.filter_by(user_id=user_id).delete()
    
    # Delete player performances
    PlayerPerformance.query.filter_by(user_id=user_id).delete()
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/teams')
@login_required
@admin_permission.require(http_exception=403)
def admin_teams():
    teams = Team.query.all()
    return render_template('admin_teams.html', teams=teams)

@app.route('/admin/teams/<int:team_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin_edit_team(team_id):
    team = Team.query.get_or_404(team_id)
    managers = User.query.filter_by(role='manager').all()
    
    if request.method == 'POST':
        team.name = request.form['name']
        team.manager_id = int(request.form['manager_id'])
        team.team_description = request.form['team_description']
        team.region = request.form['region']
        
        if 'logo' in request.files and request.files['logo'].filename:
            file = request.files['logo']
            logo_url = save_file(file)
            if logo_url:
                team.logo_url = logo_url
        
        db.session.commit()
        
        flash('Team updated successfully!', 'success')
        return redirect(url_for('admin_teams'))
    
    return render_template('admin_edit_team.html', team=team, managers=managers)

@app.route('/admin/tournaments')
@login_required
@admin_permission.require(http_exception=403)
def admin_tournaments():
    tournaments = Tournament.query.all()
    return render_template('admin_tournaments.html', tournaments=tournaments)

@app.route('/admin/tournaments/<int:tournament_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin_edit_tournament(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    managers = User.query.filter_by(role='manager').all()
    
    if request.method == 'POST':
        tournament.name = request.form['name']
        tournament.description = request.form['description']
        tournament.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M')
        tournament.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%dT%H:%M')
        tournament.game = request.form['game']
        tournament.max_teams = int(request.form['max_teams'])
        tournament.location = request.form['location']
        tournament.tournament_type = request.form['tournament_type']
        tournament.prize_pool = float(request.form['prize_pool']) if request.form['prize_pool'] else None
        tournament.status = request.form['status']
        tournament.creator_id = int(request.form['creator_id'])
        
        db.session.commit()
        
        flash('Tournament updated successfully!', 'success')
        return redirect(url_for('admin_tournaments'))
    
    return render_template('admin_edit_tournament.html', tournament=tournament, managers=managers)

@app.route('/admin/matches')
@login_required
@admin_permission.require(http_exception=403)
def admin_matches():
    matches = Match.query.all()
    return render_template('admin_matches.html', matches=matches)

@app.route('/admin/matches/<int:match_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin_edit_match(match_id):
    match = Match.query.get_or_404(match_id)
    tournaments = Tournament.query.all()
    teams = Team.query.all()
    
    if request.method == 'POST':
        match.tournament_id = int(request.form['tournament_id'])
        match.team1_id = int(request.form['team1_id'])
        match.team2_id = int(request.form['team2_id'])
        match.match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        match.venue = request.form['venue']
        match.match_type = request.form['match_type']
        match.round_number = int(request.form['round_number'])
        match.status = request.form['status']
        
        if match.status == 'completed' and 'winner_id' in request.form:
            match.winner_id = int(request.form['winner_id'])
        
        db.session.commit()
        
        flash('Match updated successfully!', 'success')
        return redirect(url_for('admin_matches'))
    
    return render_template('admin_edit_match.html', match=match, tournaments=tournaments, teams=teams)

# -------------------- PLAYER SETTINGS ROUTES --------------------

@app.route('/player/settings', methods=['GET', 'POST'])
@login_required
@player_permission.require(http_exception=403)
def player_settings():
    if request.method == 'POST':
        # Update user profile
        current_user.name = request.form['name']
        
        # Check if email is being changed
        new_email = request.form['email']
        if new_email != current_user.email:
            # Check if email already exists
            if User.query.filter(User.email == new_email, User.user_id != current_user.user_id).first():
                flash('Email already in use', 'danger')
                return redirect(url_for('player_settings'))
            current_user.email = new_email
            
        # Update other fields
        if 'date_of_birth' in request.form and request.form['date_of_birth']:
            current_user.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')
        
        if 'country' in request.form:
            current_user.country = request.form['country']
            
        if 'contact_number' in request.form:
            current_user.contact_number = request.form['contact_number']
        
        # Handle profile picture upload
        if 'profile_picture' in request.files and request.files['profile_picture'].filename:
            file = request.files['profile_picture']
            file_path = save_file(file)
            if file_path:
                current_user.profile_picture = file_path
        
        # Handle in-game name updates for team memberships
        for membership in current_user.team_memberships:
            field_name = f'in_game_name_{membership.team_id}'
            if field_name in request.form:
                membership.in_game_name = request.form[field_name]
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('player_settings'))
    
    return render_template('player_settings.html', user=current_user)

# -------------------- API ROUTES (For AJAX Updates) --------------------

@app.route('/api/matches/<int:match_id>/update-score', methods=['POST'])
@login_required
@manager_permission.require(http_exception=403)
def api_update_match_score(match_id):
    match = Match.query.get_or_404(match_id)
    tournament = Tournament.query.get_or_404(match.tournament_id)
    
    # Check if this manager created this match's tournament
    if tournament.creator_id != current_user.user_id:
        return {'error': 'Unauthorized'}, 403
    
    data = request.json
    
    # Update or create team 1 score
    team1_score = MatchScore.query.filter_by(match_id=match_id, team_id=match.team1_id).first()
    if not team1_score:
        team1_score = MatchScore(match_id=match_id, team_id=match.team1_id)
        db.session.add(team1_score)
    
    team1_score.score = data['team1_score']
    team1_score.kills = data.get('team1_kills', 0)
    team1_score.deaths = data.get('team1_deaths', 0)
    team1_score.assists = data.get('team1_assists', 0)
    team1_score.objective_points = data.get('team1_objective_points', 0)
    
    # Update or create team 2 score
    team2_score = MatchScore.query.filter_by(match_id=match_id, team_id=match.team2_id).first()
    if not team2_score:
        team2_score = MatchScore(match_id=match_id, team_id=match.team2_id)
        db.session.add(team2_score)
    
    team2_score.score = data['team2_score']
    team2_score.kills = data.get('team2_kills', 0)
    team2_score.deaths = data.get('team2_deaths', 0)
    team2_score.assists = data.get('team2_assists', 0)
    team2_score.objective_points = data.get('team2_objective_points', 0)

    # Commit the changes to the database
    db.session.commit()

    return {'message': 'Scores updated successfully'}, 200

@app.route('/api/matches/<int:match_id>/get-scores', methods=['GET'])
@login_required
@manager_permission.require(http_exception=403)
def api_get_match_scores(match_id):
    match = Match.query.get_or_404(match_id)
    
    # Check if this manager created this match's tournament
    tournament = Tournament.query.get_or_404(match.tournament_id)
    if tournament.creator_id != current_user.user_id:
        return {'error': 'Unauthorized'}, 403

    scores = {
        'team1': {
            'score': match.team1.scores[0].score if match.team1.scores else 0,
            'kills': match.team1.scores[0].kills if match.team1.scores else 0,
            'deaths': match.team1.scores[0].deaths if match.team1.scores else 0,
            'assists': match.team1.scores[0].assists if match.team1.scores else 0,
            'objective_points': match.team1.scores[0].objective_points if match.team1.scores else 0,
        },
        'team2': {
            'score': match.team2.scores[0].score if match.team2.scores else 0,
            'kills': match.team2.scores[0].kills if match.team2.scores else 0,
            'deaths': match.team2.scores[0].deaths if match.team2.scores else 0,
            'assists': match.team2.scores[0].assists if match.team2.scores else 0,
            'objective_points': match.team2.scores[0].objective_points if match.team2.scores else 0,
        }
    }

    return {'scores': scores}, 200

# -------------------- ERROR HANDLING --------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# -------------------- RUNNING THE APP --------------------

if __name__ == '__main__':
    app.run(debug=True)