import os
import re
from pathlib import Path
import requests
import yaml
from fastapi.staticfiles import StaticFiles
from site_utils import Authoricator, UserAbilities, get_logger
import fastapi
from fastapi import staticfiles
import pydantic
from dataclasses import field

app_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = fastapi.FastAPI(**app_kwargs)
logger = get_logger('Site')
app.mount("/src", StaticFiles(directory="src"), name="src")

# --- 静态配置部分 ---

# --- Proxy 配置 ---
UPSTREAM_URL_FILE = Path('proxy_url')
if UPSTREAM_URL_FILE.exists():
    logger.info(f'loading proxy url from {UPSTREAM_URL_FILE}')
CUSTOM_NODES_FILE = Path('custom_nodes.yaml')
if CUSTOM_NODES_FILE.exists():
    logger.info(f'loading custom nodes from {CUSTOM_NODES_FILE}')
# --- 密钥管理器配置 ---
VAULT_CONFIGS_DIR = Path('vault_configs')
if VAULT_CONFIGS_DIR.exists():
    logger.info(f'loading vault configs from {VAULT_CONFIGS_DIR}')
    assert VAULT_CONFIGS_DIR.is_dir()
else:
    logger.warning('no value configs found, creating...')
    VAULT_CONFIGS_DIR.mkdir(exist_ok=True)
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


# --- 认证服务 ---
@app.get('/auth',
         name='site.auth')
async def auth():
    return fastapi.responses.HTMLResponse(content=Path('templates/auth.html').read_text(encoding='utf-8'))
# --- 认证服务结束 ---


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
async def handleProxy(raw_mode: bool = False):
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
    if raw_mode:
        return fastapi.Response(upstream.content, media_type='application/x-yaml')
    proxy_conf = yaml.safe_load(upstream.text)

    if 'dns' in proxy_conf and 'fallback' in proxy_conf['dns']:
        del proxy_conf['dns']['fallback']

    # Build the “main” proxy group
    main_group = proxy_conf['proxy-groups'][0].copy()
    main_group['name'] = 'main'
    main_group['proxies'] = filterOutseaProxies(main_group['proxies'])

    cn_group = {
        'name': '🇨🇳 中国大陆',
        'type': 'select',
        'url': 'http://www.apple.com/library/test/success.html',
        'proxies': ['DIRECT']
    }
    proxy_conf['proxy-groups'] = [main_group, cn_group]

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

# --- 密钥管理器路由 ---
vault_router = fastapi.APIRouter(prefix='/vault', tags=['vault'])


class KeyConfig(pydantic.BaseModel):
    platform: str
    length: int
    symbols: str | None = field(default=None)


@vault_router.get('/',
                  name='vault.show',
                  dependencies=[fastapi.Depends(Authoricator())])
async def showVault():
    return fastapi.responses.HTMLResponse(content=Path('templates/vault.html').read_text(encoding='utf-8'))


@vault_router.get('/list',
                  name='vault.list',
                  dependencies=[fastapi.Depends(Authoricator())])
async def listVault():
    return fastapi.responses.HTMLResponse(content=Path('templates/list_vaults.html').read_text(encoding='utf-8'))


@vault_router.get('/api/key_configs',
                  name='vault.key_config.get',
                  dependencies=[fastapi.Depends(Authoricator([UserAbilities.VAULT_READ]))])
async def getVaultKeyConfigs():
    config_files = {Path(f) for f in os.listdir(VAULT_CONFIGS_DIR)}
    configs: dict[str, KeyConfig] = {}
    for config_filename in config_files:
        config_filepath = VAULT_CONFIGS_DIR / config_filename
        if not config_filepath.is_file():
            continue
        try:
            config = KeyConfig.model_validate(yaml.safe_load(config_filepath.read_text(encoding='utf-8')))
        except pydantic.ValidationError as e:
            logger.exception(f"解析 {config_filepath} 失败", exc_info=e)
            continue
        configs[config_filename.stem] = config
    return configs


def is_safe_filename(filename: str) -> bool:
    """
    只允许: 大小写字母(a-z, A-Z), 数字(0-9), 下划线(_)
    """
    # 1. 空检查 (必须做，否则空字符串可能导致逻辑错误)
    if not filename:
        return False
    # 2. 正则白名单匹配
    # re.ASCII 标志确保 \w 只匹配 ASCII 字符 (如果你改用 \w 的话)
    # 但这里直接写死 [a-zA-Z0-9_] 最稳，不受 locale 影响
    return bool(re.fullmatch(r'^[a-zA-Z0-9_]+$', filename))


@vault_router.put('/api/key_configs/{config_name}',
                  name='vault.key_config.put',
                  dependencies=[fastapi.Depends(Authoricator([UserAbilities.VAULT_CREATE]))])
async def setVaultKeyConfig(config_name: str, key_config: KeyConfig):
    if not is_safe_filename(config_name):
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_400_BAD_REQUEST,
                                    detail='非法文件名')
    config_filepath = VAULT_CONFIGS_DIR / f'{config_name}.yaml'
    if config_filepath.exists():
        raise fastapi.HTTPException(status_code=fastapi.status.HTTP_400_BAD_REQUEST,
                                    detail='配置已存在')
    with open(config_filepath, 'w', encoding='utf-8') as f:
        f.write(yaml.dump(key_config.model_dump()))
    return fastapi.responses.Response(status_code=fastapi.status.HTTP_204_NO_CONTENT)


@vault_router.delete('/api/key_configs/{config_name}',
                     name='vault.key_config.delete',
                     dependencies=[fastapi.Depends(Authoricator([UserAbilities.VAULT_DELETE]))])
async def deleteVaultKeyConfig(config_name: str):
    config_filepath = VAULT_CONFIGS_DIR / f'{config_name}.yaml'
    if not config_filepath.exists():
        return fastapi.responses.Response(status_code=fastapi.status.HTTP_204_NO_CONTENT)
    config_filepath.unlink()
    return fastapi.responses.Response(status_code=fastapi.status.HTTP_204_NO_CONTENT)

app.include_router(vault_router)
# --- 密钥管理器结束 ---
