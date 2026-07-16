VERSION = "7.4.5"
TITLE = "Linuxmuster.net API"

DESCRIPTION = """

This API provides access to a [linuxmuster.net](http://www.linuxmuster.net/)'s server management, like listing schoolclasses, users, starting an exam, etc ...
## Security

### Firewall

⚠️ In his default configuration, `linuxmuster-api` listen on port 8001. Since the API can provide sensitive information, it's **very important** to restrict the access to this port to only the clients or machines who need it.

### Authentication

The endpoints are per role and per user secured. 
Each request MUST provide a valid **JWT (JSON Web Token)** in the header (key `X-Api-Key`) to get the data.

An user can get a valid JWT token by sending username and password via Basic auth at the endpoint https://<server>:8001/v1/auth.

## First request

You are yet so far to launch your first request, just send a GET request with your JWT to [https://<server>:8001/v1/schoolclasses](/v1/schoolclasses) and you will get a whole list of all schoolclasses on the server ! Have fun with it :)
"""

HTML_HOME = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linuxmuster.net API {VERSION}</title>
    <link rel="icon" href="/static/favicon.png" type="image/png">
    <style>
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #f4f6f8;
            color: #233c4c;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}

        header {{
            background: #233c4c;
            padding: 0 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 70px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }}

        header img {{
            height: 40px;
        }}

        header .version-badge {{
            background: #ff8f00;
            color: #fff;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 20px;
            letter-spacing: 0.05em;
        }}

        .hero {{
            background: linear-gradient(135deg, #233c4c 0%, #1a2d3a 100%);
            color: #fff;
            padding: 5rem 2rem 4rem;
            text-align: center;
        }}

        .hero h1 {{
            font-size: 2.4rem;
            font-weight: 700;
            letter-spacing: -0.01em;
            margin-bottom: 0.75rem;
        }}

        .hero h1 span {{
            color: #ff8f00;
        }}

        .hero p {{
            font-size: 1.1rem;
            font-weight: 300;
            opacity: 0.85;
            max-width: 560px;
            margin: 0 auto 2rem;
            line-height: 1.6;
        }}

        .hero-actions {{
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }}

        .btn {{
            display: inline-block;
            padding: 0.75rem 1.75rem;
            border-radius: 4px;
            font-family: 'Titillium Web', sans-serif;
            font-size: 1rem;
            font-weight: 600;
            text-decoration: none;
            transition: background 0.2s, transform 0.1s;
        }}

        .btn:active {{ transform: scale(0.98); }}

        .btn-primary {{
            background: #ff8f00;
            color: #fff;
        }}

        .btn-primary:hover {{ background: #cd5d00; }}

        .btn-outline {{
            background: transparent;
            color: #fff;
            border: 2px solid rgba(255,255,255,0.4);
        }}

        .btn-outline:hover {{ border-color: #ff8f00; color: #ff8f00; }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            max-width: 1000px;
            margin: -2.5rem auto 0;
            padding: 0 2rem 4rem;
        }}

        .card {{
            background: #fff;
            border-radius: 8px;
            padding: 1.75rem;
            box-shadow: 0 2px 12px rgba(35,60,76,0.1);
            border-top: 4px solid #ff8f00;
        }}

        .card-icon {{
            font-size: 2rem;
            margin-bottom: 0.75rem;
        }}

        .card h3 {{
            font-size: 1.1rem;
            font-weight: 700;
            color: #233c4c;
            margin-bottom: 0.5rem;
        }}

        .card p {{
            font-size: 0.9rem;
            color: #5a7080;
            line-height: 1.5;
        }}

        .auth-section {{
            background: #fff;
            border-left: 4px solid #ff8f00;
            border-radius: 4px;
            max-width: 700px;
            margin: 0 auto 4rem;
            padding: 1.5rem 2rem;
            box-shadow: 0 2px 8px rgba(35,60,76,0.08);
        }}

        .auth-section h2 {{
            font-size: 1.1rem;
            font-weight: 700;
            color: #233c4c;
            margin-bottom: 0.75rem;
        }}

        .auth-section code {{
            display: block;
            background: #f4f6f8;
            border-radius: 4px;
            padding: 0.75rem 1rem;
            font-size: 0.85rem;
            color: #1a2d3a;
            word-break: break-all;
        }}

        .auth-section .note {{
            font-size: 0.82rem;
            color: #5a7080;
            margin-top: 0.6rem;
        }}

        footer {{
            margin-top: auto;
            background: #233c4c;
            color: rgba(255,255,255,0.5);
            text-align: center;
            font-size: 0.8rem;
            padding: 1.25rem;
        }}

        footer a {{
            color: #ff8f00;
            text-decoration: none;
        }}

        footer a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>

<header>
    <img src="/static/logo-text-white.png" alt="linuxmuster.net">
    <span class="version-badge">API v{VERSION}</span>
</header>

<section class="hero">
    <h1>linuxmuster.net <span>REST API</span></h1>
    <p>Manage your school infrastructure programmatically — users, classes, devices, exams, printers and more.</p>
    <div class="hero-actions">
        <a href="/docs" class="btn btn-primary">Interactive Documentation</a>
        <a href="/redoc" class="btn btn-outline">ReDoc</a>
    </div>
</section>

<div class="cards">
    <div class="card">
        <div class="card-icon">&#128100;</div>
        <h3>Users &amp; Roles</h3>
        <p>List, create and manage students, teachers, parents, staff and administrators.</p>
    </div>
    <div class="card">
        <div class="card-icon">&#127979;</div>
        <h3>Classes &amp; Groups</h3>
        <p>Access school classes, extra classes, projects and management groups.</p>
    </div>
    <div class="card">
        <div class="card-icon">&#128187;</div>
        <h3>Devices &amp; Sessions</h3>
        <p>Query registered devices and control user exam sessions on workstations.</p>
    </div>
    <div class="card">
        <div class="card-icon">&#128196;</div>
        <h3>Projects</h3>
        <p>Create and manage collaborative projects, assign members and control access across groups.</p>
    </div>
    <div class="card">
        <div class="card-icon">&#128438;</div>
        <h3>Printers</h3>
        <p>List available printers and manage memberships.</p>
    </div>
    <div class="card">
        <div class="card-icon">&#128274;</div>
        <h3>Secure by Design</h3>
        <p>JWT (HS512) authentication, per-endpoint RBAC and host key support for server-to-server calls.</p>
    </div>
</div>

<div class="auth-section">
    <h2>Quick start — get your token</h2>
    <code>POST https://&lt;server&gt;:8001/v1/auth/token<br>Authorization: Basic &lt;base64(user:password)&gt;</code>
    <p class="note">Then pass the returned JWT as <strong>X-API-Key</strong> header on every subsequent request.</p>
</div>

<footer>
    &copy; linuxmuster.net &mdash; <a href="https://www.linuxmuster.net" target="_blank">linuxmuster.net</a> &mdash; <a href="/docs">API Docs</a>
</footer>

</body>
</html>"""
