from pathlib import Path
import requests
import yaml
from site_utils import Authoricator, UserAbilities, get_logger
import fastapi
from fastapi import staticfiles

app_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = fastapi.FastAPI(**app_kwargs)
logger = get_logger('Site')

# --- 静态配置部分 ---

# --- Proxy 配置 ---
UPSTREAM_URL_FILE = Path('proxy_url')
if UPSTREAM_URL_FILE.exists():
    logger.info(f'loading proxy url from {UPSTREAM_URL_FILE}')
CUSTOM_NODES_FILE = Path('custom_nodes.yaml')
if CUSTOM_NODES_FILE.exists():
    logger.info(f'loading custom nodes from {CUSTOM_NODES_FILE}')
# --- 静态配置结束 ---


# --- 静态文件服务 ---
static_files = staticfiles.StaticFiles(directory="static")


@app.api_route("/static/{file_path:path}",
               methods=["GET", "HEAD"],
               dependencies=[fastapi.Depends(Authoricator([UserAbilities.STATIC_READ]))])
async def serve_static_protected(file_path: str, request: fastapi.Request):
    try:
        return await static_files.get_response(file_path, request.scope)
    except Exception as e:
        logger.exception(f'Error in static file', exc_info=e)
        raise fastapi.HTTPException(status_code=404, detail="File not found")
# --- 静态文件结束 ---


# --- Proxy 路由部分 ---
proxy_router = fastapi.APIRouter(prefix='/proxy', tags=['proxy'])


def filterOutseaProxies(lst):
    """Keep elements after the second string containing '-'."""
    count = 0
    for i, element in enumerate(lst):
        if '-' in element:
            count += 1
        if count == 2:
            return lst[i:]
    return []


def addNode(conf, node):
    """Append a proxy node and its name to the first proxy-group."""
    conf['proxies'].append(node)
    conf['proxy-groups'][-1]['proxies'].append(node['name'])


@proxy_router.get('/',
                  name='proxy.get',
                  dependencies=[fastapi.Depends(Authoricator([UserAbilities.PROXY_READ]))])
async def handleProxy():
    if not UPSTREAM_URL_FILE.exists():
        logger.warning(f"Proxy configuration error: UPSTREAM_URL_FILE not found.")
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_500_INTERNAL_SERVER_ERROR)
    upstream_url = UPSTREAM_URL_FILE.read_text().strip()
    if not upstream_url:
        logger.warning(f"Proxy configuration error: UPSTREAM_URL_FILE is empty.")
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Fetch the remote YAML file
    try:
        upstream = requests.get(
            upstream_url,
            headers={'user-agent': 'clash-verge/v1.3.8'},
            timeout=10
        )
        upstream.raise_for_status()
    except requests.RequestException as e:
        logger.exception('Failed to fetch upstream proxy config', exc_info=e)
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_503_SERVICE_UNAVAILABLE)

    proxy_conf = yaml.safe_load(upstream.text)

    # Minimal ruleset
    proxy_conf['rules'] = [
        'RULE-SET,AntiAd,REJECT',
        'GEOIP,LAN,DIRECT',
        'GEOIP,CN,DIRECT',
        'MATCH,main'
    ]

    if 'dns' in proxy_conf and 'fallback' in proxy_conf['dns']:
        del proxy_conf['dns']['fallback']

    # Build the “main” proxy group
    main_group = proxy_conf['proxy-groups'][0].copy()
    main_group['name'] = 'main'
    main_group['proxies'] = filterOutseaProxies(main_group['proxies'])
    proxy_conf['proxy-groups'] = [main_group]

    if CUSTOM_NODES_FILE.exists():
        custom_nodes: dict = yaml.safe_load(CUSTOM_NODES_FILE.read_text())

        for custom_node in custom_nodes['proxies']:
            addNode(proxy_conf, custom_node)

    # Serialize YAML and return
    yaml_body = yaml.dump(proxy_conf, allow_unicode=True)
    return fastapi.Response(yaml_body, media_type='application/x-yaml')


app.include_router(proxy_router)
# --- Proxy 路由结束 ---

# --- 剪贴板路由部分 ---
clipboard_router = fastapi.APIRouter(prefix='/clipboard', tags=['clipboard'])
clipboard_content = ''


@clipboard_router.get('/',
                      name='clipboard.show')
async def showClipboard():
    return fastapi.responses.HTMLResponse(content=Path('templates/cloud_clipborad.html').read_text(encoding='utf-8'))


@clipboard_router.get('/api',
                      name='clipboard.get',
                      dependencies=[fastapi.Depends(Authoricator([UserAbilities.CLIPBOARD_READ]))])
async def readClipboard():
    return fastapi.responses.PlainTextResponse(content=clipboard_content)


@clipboard_router.put('/api',
                      name='clipboard.write',
                      dependencies=[fastapi.Depends(Authoricator([UserAbilities.CLIPBOARD_WRITE]))])
async def writeClipboard(request: fastapi.Request):
    global clipboard_content
    clipboard_content = await request.body()
    return fastapi.Response(status_code=fastapi.status.HTTP_200_OK)


app.include_router(clipboard_router)
# --- 剪贴板路由结束 ---
