"""Local-only review of a saved synthetic rehearsal, never live release authority."""
import copy
import hashlib
import html
import json
import threading


def install(app):
    from fastapi import Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from aegis import app as views, auth, audit, db, proof_pack
    lock = threading.Lock()
    key = Ed25519PrivateKey.generate()
    def pack(request):
        path = views.demo_result_path(request)
        if not path.is_file():
            return None
        return json.loads(path.read_text())
    def digest(saved):
        return hashlib.sha256(json.dumps(saved, sort_keys=True).encode()).hexdigest()
    @app.get('/local-demo', response_class=HTMLResponse)
    async def panel(request: Request):
        user, redirect = views.need_login(request)
        if redirect:
            return redirect
        saved = pack(request)
        body = '<h1>Offline Lumen oversight</h1><p>Scripted stand-in. Synthetic data and actions. No live AI or outside effects.</p>'
        body += '<p><a href="/admin/demo">Run five stories first</a> | <a href="/admin/demo/source">Source</a> | <a href="/admin/demo/guard">Aegis / Delta</a> | <a href="/admin/demo/briefing">Morning briefing</a> | <a href="/audit">Audit</a></p>'
        if saved and 'scenarios' in saved.get('result', {}):
            result = saved['result']
            body += '<h2>Four moments: actual saved decisions</h2><p>Source/rogue-content oversight, stopped risky actions, unsupported numbers/contradictions, morning briefing. Contract gaps remain explicit below.</p>'
            body += '<pre>' + html.escape(json.dumps(result['scenarios'], indent=2)) + '</pre>'
            body += '<h2>Aegis / Delta proof</h2><pre>' + html.escape(json.dumps(result['guards'], indent=2)) + '</pre>'
            body += '<h2>Morning briefing</h2><pre>' + html.escape(json.dumps(result['briefing'], indent=2)) + '</pre>'
            ident = digest(saved)
            reviews = json.loads(db.get_setting('local-demo-review:' + ident, '[]'))
            body += '<h2>Two-person approval of this synthetic proof pack</h2><p>This approves the review pack only. It never releases a held action.</p>'
            body += '<p>Distinct named approvers: ' + html.escape(', '.join(reviews)) + '; status: ' + ('approved' if len(reviews) == 2 else 'held') + '</p>'
            body += f'<form method="post" action="/local-demo/review"><input type="hidden" name="csrf" value="{html.escape(user["csrf"])}"><input type="hidden" name="digest" value="{ident}"><label>Password <input type="password" name="password"></label><button>Approve synthetic pack review</button></form>'
            signed = {'payload': saved, 'algorithm': 'Ed25519', 'key_id': hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()}
            import base64
            artifact = dict(signed, signature=base64.b64encode(key.sign(proof_pack._canonical(signed))).decode())
            original = proof_pack._canonical(artifact)
            altered = copy.deepcopy(artifact)
            altered['payload']['result']['sent'] += 1
            valid = proof_pack.verify_seal(original, key.public_key())
            invalid = proof_pack.verify_seal(proof_pack._canonical(altered), key.public_key())
            body += f'<h2>Copied proof tamper test</h2><p>Original seal valid: {valid}. Modified COPY seal valid: {invalid}. Main history unchanged.</p>'
        return HTMLResponse('<main>' + body + '</main>')
    @app.post('/local-demo/review')
    async def review(request: Request):
        user, redirect = views.need_login(request)
        if redirect:
            return redirect
        form = await request.form()
        saved = pack(request)
        if user['role'] != 'approver' or user['username'] not in ('ops', 'riley') or not auth.check_csrf(user, form.get('csrf', '')):
            return HTMLResponse('Named approver and CSRF required', status_code=403)
        if not auth._verify_pw(form.get('password', ''), bytes.fromhex(user['salt']), user['pw_hash']):
            return HTMLResponse('Reauthentication failed', status_code=403)
        if not saved or form.get('digest') != digest(saved):
            return HTMLResponse('Saved pack changed; review again', status_code=409)
        with lock:
            setting = 'local-demo-review:' + digest(saved)
            reviews = json.loads(db.get_setting(setting, '[]'))
            if user['username'] in reviews:
                return HTMLResponse('Duplicate identity cannot count twice', status_code=409)
            reviews.append(user['username'])
            db.set_setting(setting, json.dumps(reviews), user['username'], 0)
            audit.record('local_demo_pack_reviewed', {'by': user['username'], 'digest': digest(saved), 'count': len(reviews), 'synthetic_only': True})
        return RedirectResponse('/local-demo', status_code=303)
