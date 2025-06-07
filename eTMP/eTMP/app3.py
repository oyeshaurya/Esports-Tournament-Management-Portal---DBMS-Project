from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission, RoleNeed
from datetime import datetime, timedelta
import uuid

# Initialize Flask app
app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Generate a secure random secret key

# Database Configuration (Update as per your MySQL credentials)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:SQLpass1@localhost/esports_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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
        return self.user_id

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
    
    # Relationships
    registrations = db.relationship('TournamentRegistration', back_populates='tournament', lazy='dynamic')
    matches = db.relationship('Match', back_populates='tournament', lazy='dynamic')
    standings = db.relationship('TournamentStanding', back_populates='tournament', lazy='dynamic')
    game_statistics = db.relationship('GameStatistic', back_populates='tournament', lazy='dynamic')

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

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- NEW ROUTES --------------------

@app.route('/add_match_score', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def add_match_score():
    if request.method == 'POST':
        match_id = request.form['match_id']
        team_id = request.form['team_id']
        score = request.form['score']
        map_name = request.form['map_name']
        kills = request.form['kills']
        deaths = request.form['deaths']
        assists = request.form['assists']
        objective_points = request.form['objective_points']
        round_wins = request.form['round_wins']
        
        new_score = MatchScore(
            match_id=match_id,
            team_id=team_id,
            score=score,
            map_name=map_name,
            kills=kills,
            deaths=deaths,
            assists=assists,
            objective_points=objective_points,
            round_wins=round_wins
        )
        
        db.session.add(new_score)
        db.session.commit()
        
        flash('Match score added successfully!', 'success')
        return redirect(url_for('tournament_details', tournament_id=Match.query.get(match_id).tournament_id))
    
    # Get matches where current user is a manager
    managed_teams = Team.query.filter_by(manager_id=current_user.user_id).all()
    matches = Match.query.filter(
        Match.team1_id.in_([team.team_id for team in managed_teams]) | 
        Match.team2_id.in_([team.team_id for team in managed_teams])
    ).all()
    
    return render_template('add_match_score.html', matches=matches)

@app.route('/add_player_performance', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def add_player_performance():
    if request.method == 'POST':
        match_id = request.form['match_id']
        user_id = request.form['user_id']
        team_id = request.form['team_id']
        kills = request.form['kills']
        deaths = request.form['deaths']
        assists = request.form['assists']
        headshots = request.form['headshots']
        accuracy = request.form['accuracy']
        damage_dealt = request.form['damage_dealt']
        healing_done = request.form['healing_done']
        time_played = request.form['time_played']
        
        new_performance = PlayerPerformance(
            match_id=match_id,
            user_id=user_id,
            team_id=team_id,
            kills=kills,
            deaths=deaths,
            assists=assists,
            headshots=headshots,
            accuracy=accuracy,
            damage_dealt=damage_dealt,
            healing_done=healing_done,
            time_played=time_played
        )
        
        db.session.add(new_performance)
        db.session.commit()
        
        flash('Player performance added successfully!', 'success')
        return redirect(url_for('tournament_details', tournament_id=Match.query.get(match_id).tournament_id))
    
    # Get matches and players for managed teams
    managed_teams = Team.query.filter_by(manager_id=current_user.user_id).all()
    matches = Match.query.filter(
        Match.team1_id.in_([team.team_id for team in managed_teams]) | 
        Match.team2_id.in_([team.team_id for team in managed_teams])
    ).all()
    
    # Get players from managed teams
    team_members = TeamMember.query.filter(
        TeamMember.team_id.in_([team.team_id for team in managed_teams])
    ).all()
    
    return render_template('add_player_performance.html', matches=matches, team_members=team_members)

@app.route('/tournament_standings/<int:tournament_id>', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def update_tournament_standings(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    if request.method == 'POST':
        team_id = request.form['team_id']
        final_rank = request.form['final_rank']
        points = request.form['points']
        matches_played = request.form['matches_played']
        matches_won = request.form['matches_won']
        matches_lost = request.form['matches_lost']
        
        # Check if standing already exists
        existing_standing = TournamentStanding.query.filter_by(
            tournament_id=tournament_id, 
            team_id=team_id
        ).first()
        
        if existing_standing:
            # Update existing standing
            existing_standing.final_rank = final_rank
            existing_standing.points = points
            existing_standing.matches_played = matches_played
            existing_standing.matches_won = matches_won
            existing_standing.matches_lost = matches_lost
        else:
            # Create new standing
            new_standing = TournamentStanding(
                tournament_id=tournament_id,
                team_id=team_id,
                final_rank=final_rank,
                points=points,
                matches_played=matches_played,
                matches_won=matches_won,
                matches_lost=matches_lost
            )
            db.session.add(new_standing)
        
        db.session.commit()
        
        flash('Tournament standings updated successfully!', 'success')
        return redirect(url_for('tournament_details', tournament_id=tournament_id))
    
    # Get registered teams for this tournament
    registered_teams = [reg.team for reg in tournament.registrations]
    
    return render_template('update_tournament_standings.html', 
                           tournament=tournament, 
                           teams=registered_teams)

@app.route('/game_statistics/<int:tournament_id>', methods=['GET', 'POST'])
@login_required
@manager_permission.require(http_exception=403)
def add_game_statistics(tournament_id):
    tournament = Tournament.query.get_or_404(tournament_id)
    
    if request.method == 'POST':
        total_matches = request.form['total_matches']
        total_teams = request.form['total_teams']
        total_players = request.form['total_players']
        average_match_duration = request.form['average_match_duration']
        most_picked_character = request.form['most_picked_character']
        most_banned_character = request.form['most_banned_character']
        
        # Check if statistics already exist
        existing_stats = GameStatistic.query.filter_by(tournament_id=tournament_id).first()
        
        if existing_stats:
            # Update existing statistics
            existing_stats.total_matches = total_matches
            existing_stats.total_teams = total_teams
            existing_stats.total_players = total_players
            existing_stats.average_match_duration = average_match_duration
            existing_stats.most_picked_character = most_picked_character
            existing_stats.most_banned_character = most_banned_character
        else:
            # Create new game statistics
            new_stats = GameStatistic(
                tournament_id=tournament_id,
                total_matches=total_matches,
                total_teams=total_teams,
                total_players=total_players,
                average_match_duration=average_match_duration,
                most_picked_character=most_picked_character,
                most_banned_character=most_banned_character
            )
            db.session.add(new_stats)
        
        db.session.commit()
        
        flash('Game statistics added successfully!', 'success')
        return redirect(url_for('tournament_details', tournament_id=tournament_id))
    
    return render_template('add_game_statistics.html', tournament=tournament)

# Modify existing routes to include new information

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if request.method == 'POST':
        # Update user profile
        current_user.name = request.form['name']
        current_user.country = request.form['country']
        current_user.contact_number = request.form['contact_number']
        current_user.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d')
        
        # Handle profile picture upload (you'll need to implement file upload logic)
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            # Implement file saving logic
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))
    
    return render_template('user_profile.html')

# Existing routes remain the same, but you might want to update some to include new fields

# -------------------- MAIN --------------------

if __name__ == '__main__':
    app.run(debug=True)