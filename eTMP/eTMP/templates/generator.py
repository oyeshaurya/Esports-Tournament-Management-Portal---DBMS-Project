import os

html_files = [
    'home.html',
    'login.html',
    'register.html',
    'player_dashboard.html',
    'manager_dashboard.html',
    'admin_dashboard.html',
    'user_profile.html',
    'change_password.html',
    'player_team_view.html',
    'player_tournament_view.html',
    'player_match_view.html',
    'manager_tournaments.html',
    'create_tournament.html',
    'edit_tournament.html',
    'view_tournament.html',
    'manager_teams.html',
    'create_team.html',
    'edit_team.html',
    'view_team.html',
    'add_team_member.html',
    'player_settings.html',
    'admin_users.html',
    'admin_edit_user.html',
    'admin_teams.html',
    'admin_edit_team.html',
    'admin_tournaments.html',
    'admin_edit_tournament.html',
    'admin_matches.html',
    'admin_edit_match.html',
    '404.html',
    '403.html'
]

templates_dir = 'templates'

os.makedirs(templates_dir, exist_ok=True)

for file in html_files:
    with open(os.path.join(templates_dir, file), 'w') as f:
        f.write(f'<!-- {file} template -->\n')
        f.write('<h1>Welcome to the {file.replace(".html", "").replace("_", " ").title()} Page</h1>\n')