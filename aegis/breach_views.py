"""G2 human-only screen. Mount explicitly with app.include_router(make_router(render))."""
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import auth, breach_incident, evidence, incident_store
from .breach_clock import SG
from .breach_prefill import pdpc_fact_prefill


def _date(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=SG)
    return parsed.astimezone(SG)


def make_router(render):
    """Use host rendering, cookie authentication and existing incident storage only."""
    router = APIRouter()

    def user_for(request, write=False):
        if 'X-Agent-Token' in request.headers:
            raise HTTPException(403, 'Human session required')
        user = auth.user_by_token(request.cookies.get('aegis_session', ''))
        if user is None:
            raise HTTPException(401, 'Sign in required')
        if user['must_change'] or user['role'] not in (('admin',) if write else ('admin', 'approver', 'auditor')):
            raise HTTPException(403, 'Incident access refused')
        return user

    def storage(call):
        try:
            return call()
        except PermissionError:
            raise HTTPException(403, 'Incident access refused') from None
        except KeyError:
            raise HTTPException(404, 'Incident not found') from None
        except (incident_store.IncidentIntegrityError, evidence.EvidenceKeyError):
            raise HTTPException(503, 'Incident storage verification unavailable; no success confirmed') from None
        except ValueError:
            raise HTTPException(422, 'Invalid incident facts or dates') from None

    @router.get('/breach-clock')
    @router.get('/breach-clock/{incident_id}')
    def screen(request: Request, incident_id: str | None = None):
        user = user_for(request)
        incident = storage(lambda: incident_store.get_incident(user, incident_id)) if incident_id else None
        incidents = storage(lambda: incident_store.list_incidents(user)) if not incident else []
        now = datetime.now(SG)
        return render(request, 'breach_clock.html', user, incident=incident, incidents=incidents,
                      completion=storage(lambda: breach_incident.completion(incident, now)) if incident else None,
                      prefill=pdpc_fact_prefill(incident),
                      clock=storage(lambda: breach_incident.project(incident, now)) if incident else None,
                      as_of=now.isoformat())

    @router.post('/breach-clock')
    @router.post('/breach-clock/{incident_id}/steps')
    async def save(request: Request, incident_id: str | None = None):
        user = user_for(request, write=True)
        form = await request.form()
        if not auth.check_csrf(user, str(form.get('csrf', ''))):
            raise HTTPException(403, 'Bad CSRF token')
        try:
            now = datetime.now(SG)
            awareness = _date(form.get('awareness_at'))
            determination = _date(form.get('determination_at'))
            for date, flag in ((awareness, 'human_awareness'), (determination, 'human_determination')):
                if (date is not None) != (form.get(flag) == 'yes') or (date and date > now):
                    raise ValueError('Explicit human confirmation required')
            harm = str(form.get('harm', ''))
            if harm not in ('', 'yes', 'no'):
                raise ValueError('Invalid harm')
            count = str(form.get('count', ''))
            facts = dict(count=int(count) if count else None, data=form.get('data') if 'data' in form else None,
                         harm={'': None, 'yes': True, 'no': False}[harm])
            values = dict(facts=facts, timestamp=now.timestamp(),
                awareness_at=awareness.timestamp() if awareness else None, human_awareness=awareness is not None,
                determination_at=determination.timestamp() if determination else None,
                human_determination=determination is not None)
            text = str(form.get('text', ''))
        except (ValueError, TypeError, OverflowError):
            raise HTTPException(422, 'Invalid incident facts or dates') from None
        token = request.cookies.get('aegis_session', '')
        csrf = str(form.get('csrf', ''))
        # No await inside the adapter's continuous read/validate/commit RLock.
        if form.get('outcome') == 'not_notifiable':
            if not incident_id or awareness or determination:
                raise HTTPException(422, 'Completion requires an existing incident and separate triggers')
            try:
                storage(lambda: breach_incident.complete_assessment(token, csrf, incident_id,
                    reason=str(form.get('reason', '')), completed_at=_date(form.get('completed_at')).timestamp()
                    if form.get('completed_at') else None, human_confirmed=form.get('human_completion') == 'yes'))
            except OverflowError:
                raise HTTPException(422, 'Invalid incident facts or dates') from None
        elif form.get('outcome'):
            raise HTTPException(422, 'Invalid outcome')
        elif incident_id:
            storage(lambda: breach_incident.add_step(token, csrf, incident_id, step=text, **values))
        else:
            incident_id = storage(lambda: breach_incident.create_incident(token, csrf, title=text, **values))['id']
        return RedirectResponse('/breach-clock/' + incident_id, status_code=303)

    return router
