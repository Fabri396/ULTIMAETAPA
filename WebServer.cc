#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>

static const char* html = R"HTML(<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TicAmazon | Monitoreo</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,Arial,sans-serif;background:#f4f6fa;color:#172238;margin:0}
header{background:#152b4a;color:white;padding:25px max(20px,calc((100% - 1040px)/2))}
header h1{margin:0;font-size:27px}header p{margin:6px 0 0;color:#c6d6eb}
main{max-width:1040px;margin:28px auto;padding:0 20px}
h2{font-size:18px;margin:26px 0 14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}
.card{background:white;border:1px solid #e0e5ee;border-radius:12px;padding:19px;box-shadow:0 2px 6px #1722380a}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px}
.name{font-weight:750;font-size:20px}.badge{font-size:12px;font-weight:700;padding:5px 10px;border-radius:20px}
.online{background:#d9f5e7;color:#086c41}.offline{background:#fce2e2;color:#a42323}
.meta{color:#62718a;font-size:14px;margin-top:12px}.tags{display:flex;flex-wrap:wrap;gap:7px;margin-top:13px}
.tag{background:#eaf0fa;border-radius:6px;padding:5px 9px;font-size:13px}
.tagbutton{border:0;cursor:pointer;color:#154578}.tagbutton:hover{text-decoration:underline}.product{padding:12px;border-top:1px solid #e0e5ee}.product strong{display:block}.product small{color:#62718a}#details{margin-top:20px}#updated{font-size:13px;color:#63718a}#error{color:#a42323}
</style></head><body><header><h1>TicAmazon · Monitoreo de servidores</h1>
<p>Estado en tiempo real del intermediario y las bodegas registradas</p></header>
<main><div id="updated">Conectando...</div><div id="error"></div>
<h2>Servidor intermediario</h2><div id="intermediary" class="grid"></div>
<h2>Bodegas registradas</h2><div id="warehouses" class="grid"></div><section id="details" aria-live="polite"></section></main>
<script>
function safe(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function card(name,online,details,tags){
return `<div class="card"><div class="top"><span class="name">${safe(name)}</span><span class="badge ${online?'online':'offline'}">${online?'En línea':'Desconectado'}</span></div>
<div class="meta">${safe(details)}</div><div class="tags">${tags.map(t=>`<button class="tag tagbutton" data-warehouse="${safe(name)}" data-category="${safe(t)}">${safe(t)}</button>`).join('')}</div></div>`}
let selected=null;
let lastStatus='';
let lastProducts='';
let loadingProducts=false;
document.addEventListener('click',e=>{
const b=e.target.closest('[data-warehouse][data-category]');
if(!b)return;
const warehouse=b.dataset.warehouse,category=b.dataset.category;
if(selected&&selected.warehouse===warehouse&&selected.category===category)return;
selected={warehouse,category};
lastProducts='';
document.getElementById('details').innerHTML='<h2>'+safe(warehouse)+' / '+safe(category)+'</h2><p>Cargando productos...</p>';
loadProducts();
});
async function loadProducts(){
if(!selected||loadingProducts)return;
loadingProducts=true;
const warehouse=selected.warehouse,category=selected.category;
const panel=document.getElementById('details');
try{
const url='/api/products?warehouse='+encodeURIComponent(warehouse)+'&category='+encodeURIComponent(category);
const response=await fetch(url,{cache:'no-store'});
const data=await response.json();
if(!selected||selected.warehouse!==warehouse||selected.category!==category)return;
if(!response.ok)throw Error(data.error||'No se pudo consultar la bodega');
const signature=JSON.stringify(data.products);
if(signature===lastProducts)return;
lastProducts=signature;
panel.innerHTML='<h2>'+safe(warehouse)+' / '+safe(category)+'</h2>'+
(data.products.length?'<div class="card">'+data.products.map(p=>'<div class="product"><strong>'+safe(p.name)+'</strong><small>Existencias: '+safe(p.stock)+' · Precio: '+safe(p.price)+' · Ubicación: '+safe(p.location)+'</small><div>'+safe(p.description)+'</div></div>').join('')+'</div>':'<p>No hay productos en esta categoría.</p>');
}catch(e){
if(selected&&selected.warehouse===warehouse&&selected.category===category){
const msg='<h2>'+safe(warehouse)+' / '+safe(category)+'</h2><p class="error">'+safe(e.message)+'</p>';
if(panel.innerHTML!==msg){panel.innerHTML=msg;lastProducts='';}
}
}finally{loadingProducts=false;}
}
async function refresh(){
try{
const response=await fetch('/api/status',{cache:'no-store'});
if(!response.ok)throw Error('HTTP '+response.status);
const data=await response.json();
const signature=JSON.stringify(data);
if(signature!==lastStatus){
lastStatus=signature;
document.getElementById('intermediary').innerHTML=card(data.intermediary.id,data.intermediary.online,'Puerto TLS: '+data.intermediary.port,[]);
document.getElementById('warehouses').innerHTML=data.warehouses.length
?data.warehouses.map(w=>card(w.id,w.online,w.host+':'+w.port,w.categories)).join('')
:'<p>Aún no hay bodegas registradas.</p>';
}
document.getElementById('updated').textContent='Última comprobación: '+new Date().toLocaleTimeString('es-CR')+' · Cada 2 segundos';
document.getElementById('error').textContent='';
if(selected){
const w=data.warehouses.find(w=>w.id===selected.warehouse);
if(w&&w.online)loadProducts();
}
}catch(e){document.getElementById('error').textContent='No se pudo actualizar el estado: '+e.message;}
}
refresh();setInterval(refresh,2000);
</script></body></html>)HTML";

static std::string fetchApi(const std::string& path, int& code) {
    const int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0){code=503;return "{\"error\":\"Sin conexion con intermediario\"}";}
    sockaddr_in addr={};
    addr.sin_family=AF_INET;
    addr.sin_port=htons(8082);
    inet_pton(AF_INET,"127.0.0.1",&addr.sin_addr);
    timeval timeout={3,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    if(connect(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0){
        close(fd);code=503;return "{\"error\":\"Intermediario no disponible\"}";
    }
    std::string req="GET "+path+" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    send(fd,req.data(),req.size(),MSG_NOSIGNAL);
    std::string response;char buffer[4096];ssize_t n;
    while((n=recv(fd,buffer,sizeof(buffer),0))>0 && response.size()<1024*1024)
        response.append(buffer,n);
    close(fd);
    size_t sep=response.find("\r\n\r\n");
    if(sep==std::string::npos){code=502;return "{\"error\":\"Respuesta invalida del intermediario\"}";}
    code=response.compare(9,3,"200")==0?200:502;
    return response.substr(sep+4);
}
static void handle(int fd) {
    timeval timeout={3,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    char buffer[2048];ssize_t n=recv(fd,buffer,sizeof(buffer)-1,0);
    if(n<=0){close(fd);return;}buffer[n]=0;
    std::istringstream request(buffer);
    std::string method,path;request>>method>>path;
    const bool api=path=="/api/status"||path.compare(0,14,"/api/products?")==0;
    int code=200;
    std::string body;
    if(method!="GET"){code=405;body="Metodo no permitido";}
    else if(path=="/"){body=html;}
    else if(api){body=fetchApi(path,code);}
    else {code=404;body="No encontrado";}
    std::string header="HTTP/1.1 "+std::to_string(code)+(code==200?" OK":" Error")+
      "\r\nContent-Type: "+(api?"application/json":"text/html")+
      "; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: "+
      std::to_string(body.size())+"\r\n\r\n";
    const std::string response=header+body;
    size_t sent=0;
    while(sent<response.size()){
        ssize_t count=send(fd,response.data()+sent,response.size()-sent,MSG_NOSIGNAL);
        if (count <= 0) {
            break;
        }
        sent += static_cast<size_t>(count);
    }
    close(fd);
}
int main(){
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0){std::cerr<<"Error creando socket\n";return 1;}
    int reuse=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    sockaddr_in addr={};addr.sin_family=AF_INET;addr.sin_port=htons(8081);
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0||listen(fd,16)!=0){
        std::cerr<<"No se pudo abrir puerto 8081\n";close(fd);return 1;
    }
    std::cout<<"TicAmazon Web: http://localhost:8081\n";
    while(true){int client=accept(fd,nullptr,nullptr);if(client>=0)std::thread(handle,client).detach();}
}
