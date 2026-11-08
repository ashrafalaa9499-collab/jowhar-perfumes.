import os,json,sqlite3,hashlib,secrets,base64,time,re,mimetypes
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from http.cookies import SimpleCookie
R=os.path.dirname(os.path.abspath(__file__));D=os.environ.get('DATA_DIR',R+'/data');os.makedirs(D+'/uploads',exist_ok=True)
db=sqlite3.connect(D+'/jowhar.db',check_same_thread=False);db.row_factory=sqlite3.Row
db.executescript('create table if not exists admin(id integer primary key,u text,h text);create table if not exists kv(k text primary key,v text);create table if not exists items(id integer primary key,t text,d text);')
def hp(p,s=None):
    s=s or secrets.token_hex(16);return s+'$'+hashlib.scrypt(p.encode(),salt=s.encode(),n=2**14,r=8,p=1).hex()
def chk(p,h):s=h.split('$')[0];return secrets.compare_digest(hp(p,s),h)
if not db.execute('select 1 from admin').fetchone():
    u,p=os.environ.get('ADMIN_USER'),os.environ.get('ADMIN_PASSWORD')
    if u and p:db.execute('insert into admin(u,h) values(?,?)',(u,hp(p)));db.commit()
    else:print('!! Set ADMIN_USER and ADMIN_PASSWORD env vars before first run')
if not db.execute("select 1 from items where t='link'").fetchone():
    for i,(k,u) in enumerate(json.load(open(R+'/links.json'))):
        db.execute('insert into items(t,d) values(?,?)',('link',json.dumps({'key':k,'url':u,'on':1,'footer':1,'contact':1,'order':i})))
    db.commit()
S={};F={}
def items():
    o={'product':[],'branch':[],'link':[]}
    for r in db.execute('select * from items order by id desc'):o[r['t']].append({**json.loads(r['d']),'id':r['id']})
    o['link'].sort(key=lambda x:x.get('order',0));return o
def content():return {r['k']:r['v'] for r in db.execute('select * from kv')}
class H(BaseHTTPRequestHandler):
    def log_message(s,*a):pass
    def send(s,c,b,t='application/json',x=None):
        if not isinstance(b,bytes):b=json.dumps(b).encode()
        s.send_response(c);s.send_header('Content-Type',t);s.send_header('Content-Length',str(len(b)))
        s.send_header('X-Content-Type-Options','nosniff');s.send_header('X-Frame-Options','DENY')
        for h in x or []:s.send_header(*h)
        s.end_headers();s.wfile.write(b)
    def sess(s):
        c=SimpleCookie(s.headers.get('Cookie',''));m=c.get('sid');return m and S.get(m.value)
    def do_GET(s):
        p=s.path.split('?')[0]
        if p=='/api/public':return s.send(200,{'items':items(),'content':content()})
        if p=='/api/me':return s.send(200,{'ok':bool(s.sess())})
        if p=='/robots.txt':return s.send(200,b'User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: /sitemap.xml\n','text/plain')
        if p=='/sitemap.xml':
            b=s.headers.get('Host','');u=''.join('<url><loc>http://%s/#/%s</loc></url>'%(b,x) for x in['','perfumes','makeup','branches','about','contact'])
            return s.send(200,('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">%s</urlset>'%u).encode(),'application/xml')
        f={'/':'index.html','/admin':'admin.html'}.get(p)
        if not f and p.startswith('/uploads/'):f=None;fp=os.path.join(D,'uploads',os.path.basename(p))
        elif not f and re.fullmatch(r'/[\w.-]+\.(js|css|svg|png|jpg|webp|ico)',p):fp=R+'/public'+p
        elif f:fp=R+'/public/'+f
        else:return s.send(404,{'e':'not found'})
        if not os.path.isfile(fp):return s.send(404,{'e':'not found'})
        s.send(200,open(fp,'rb').read(),mimetypes.guess_type(fp)[0] or 'application/octet-stream',[('Cache-Control','public,max-age=300' if '/uploads/' in p else 'no-cache')])
    def do_POST(s):
        p=s.path
        if 'json' not in s.headers.get('Content-Type',''):return s.send(400,{'e':'bad type'})
        try:d=json.loads(s.rfile.read(int(s.headers.get('Content-Length',0)) or 0) or b'{}')
        except Exception:return s.send(400,{'e':'bad json'})
        if p=='/api/login':
            ip=s.client_address[0];F[ip]=[t for t in F.get(ip,[]) if time.time()-t<600]
            if len(F[ip])>=8:return s.send(429,{'e':'many attempts'})
            r=db.execute('select * from admin where u=?',(d.get('u',''),)).fetchone()
            if r and chk(d.get('p',''),r['h']):
                k=secrets.token_urlsafe(32);S[k]=r['id']
                return s.send(200,{'ok':1},x=[('Set-Cookie','sid=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'%k)])
            F[ip].append(time.time());return s.send(401,{'e':'invalid'})
        if p=='/api/logout':
            c=SimpleCookie(s.headers.get('Cookie',''));S.pop(c['sid'].value,None) if 'sid' in c else 0
            return s.send(200,{'ok':1},x=[('Set-Cookie','sid=; Max-Age=0; Path=/')])
        if not s.sess():return s.send(401,{'e':'unauthorized'})
        if p=='/api/admin/item':
            t=d.get('t')
            if t not in('product','branch','link'):return s.send(400,{'e':'type'})
            x=json.dumps(d['d'])
            if d.get('id'):db.execute('update items set d=? where id=? and t=?',(x,d['id'],t))
            else:db.execute('insert into items(t,d) values(?,?)',(t,x))
            db.commit();return s.send(200,{'ok':1})
        if p=='/api/admin/delete':db.execute('delete from items where id=?',(d['id'],));db.commit();return s.send(200,{'ok':1})
        if p=='/api/admin/content':
            for k,v in d.items():db.execute('insert or replace into kv values(?,?)',(k,str(v)))
            db.commit();return s.send(200,{'ok':1})
        if p=='/api/admin/upload':
            ext=os.path.splitext(d.get('name',''))[1].lower()
            if ext not in('.jpg','.jpeg','.png','.webp','.svg'):return s.send(400,{'e':'type'})
            b=base64.b64decode(d['data'])
            if len(b)>6_000_000:return s.send(400,{'e':'size'})
            n=secrets.token_hex(8)+ext;open(D+'/uploads/'+n,'wb').write(b);return s.send(200,{'url':'/uploads/'+n})
        if p=='/api/admin/account':
            u,pw=d.get('u','').strip(),d.get('p','')
            if len(u)<3 or len(pw)<12:return s.send(400,{'e':'weak'})
            db.execute('update admin set u=?,h=?',(u,hp(pw)));db.commit();return s.send(200,{'ok':1})
        s.send(404,{'e':'nf'})
if __name__=='__main__':
    ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT',8000))),H).serve_forever()
