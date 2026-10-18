"""Generate design diagrams, not execution screenshots."""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

FONT='/System/Library/Fonts/Supplemental/Arial.ttf'
def font(size):
    try:
        return ImageFont.truetype(FONT,size)
    except OSError:
        return ImageFont.load_default(size=size)

def diagram(path,title,boxes,edges,size):
    image=Image.new('RGB',size,'#f7fafc')
    d=ImageDraw.Draw(image)
    d.text((35,25),title,font=font(30),fill='#12263a')
    d.text((35,68),'Joseph Awaida | Sprint I | Design diagram',font=font(17),fill='#526879')
    for start,end,label in edges:
        a=boxes[start][0]; b=boxes[end][0]
        x1=(a[0]+a[2])/2; y1=(a[1]+a[3])/2
        x2=(b[0]+b[2])/2; y2=(b[1]+b[3])/2
        d.line((x1,y1,x2,y2),fill='#6a869a',width=3)
        if label:
            x=(x1+x2)/2; y=(y1+y2)/2
            bounds=d.textbbox((x,y),label,font=font(15))
            d.rectangle((bounds[0]-4,bounds[1]-3,bounds[2]+4,bounds[3]+3),fill='#f7fafc')
            d.text((x,y),label,font=font(15),fill='#24445b')
    for rect,heading,lines in boxes.values():
        d.rounded_rectangle(rect,radius=10,fill='white',outline='#3b617a',width=2)
        x,y,_,_=rect
        d.text((x+14,y+12),heading,font=font(22),fill='#123b56')
        for i,line in enumerate(lines):
            d.text((x+14,y+48+24*i),line,font=font(16),fill='#263e4e')
    image.save(path)

def generate():
    boxes={
      'client':((410,120,810,240),'Postman / API clients',['HTTP requests + bearer tokens']),
      'auth':((30,340,300,470),'Identity adapter :8000',['Login + local token sessions']),
      'v':((325,340,595,470),'Service 7 :8007',['Vulnerabilities + remediation']),
      'n':((620,340,890,470),'Service 8 :8008',['Notifications + read tracking']),
      'p':((915,340,1185,470),'Service 9 :8009',['Playbooks + ordered actions']),
      'db':((340,600,880,770),'Shared SQLite database',['Owned service tables + reference identities/assets','Local audit records; retained action history']),
      'worker':((340,820,880,945),'Notification delivery worker',['Retries queued vulnerability alerts through HTTP','Idempotency receipts prevent duplicate notifications']),
      'team':((340,1020,880,1160),'Team integration boundaries',['Services 1, 2, 5: agreed HTTP contracts pending','Upstream events call notification HTTP API'])}
    edges=[('client',k,'HTTP') for k in ('auth','v','n','p')]+[(k,'db','') for k in ('auth','v','n','p')]+[('db','worker',''),('worker','n','HTTP'),('worker','team','')]
    diagram('docs/architecture.png','Service architecture',boxes,edges,(1220,1200))
    boxes={
      'users':((460,120,790,350),'users (reference)',['PK id | UNIQUE username','full_name, password_hash','role, account_status']),
      'assets':((40,440,350,620),'assets (reference)',['PK id | FK owner_id -> users','name']),
      'sessions':((900,120,1210,300),'sessions',['PK token_hash','FK user_id -> users','expires_at']),
      'v':((40,780,420,1090),'vulnerabilities',['PK id | FK asset_id -> assets','title, description, CVE, CVSS','severity, discovery_source','status, created_at','resolution_date']),
      'n':((460,440,800,700),'notifications',['PK id | FK user_id -> users','title, message, type, severity','status, created_at, read_date']),
      'p':((900,440,1250,700),'playbooks',['PK id | FK created_by -> users','name, description, category','severity, created_at']),
      'a':((900,820,1250,1110),'actions',['PK id | FK playbook_id','FK assigned_user_id -> users','description, step_number','status, completion_date','UNIQUE(playbook_id, step_number)']),
      'h':((460,1220,830,1500),'action_history (retained)',['PK id | FK actor_id -> users','FK assigned_user_id -> users','action_id, playbook_id: retained IDs','old_status, new_status, recorded_at']),
      'outbox':((40,1620,550,1820),'notification_outbox',['PK event_id | JSON payload','status, attempts, last_error, timestamps']),
      'receipts':((700,1620,1210,1820),'notification_receipts',['PK event_id | payload_hash','original response_json; duplicate protection']),
      'audit':((40,1240,390,1480),'audit_logs (local adapter)',['PK id | FK user_id -> users','action, description, severity','related_service, created_at'])}
    edges=[('users','assets','1:N'),('users','sessions','1:N'),('assets','v','1:N'),('users','n','1:N'),('users','p','1:N'),('p','a','1:N'),('a','h','IDs retained'),('users','audit','1:N')]
    diagram('docs/schema.png','Relational schema and integration references',boxes,edges,(1290,1870))

if __name__=='__main__':
    generate()
