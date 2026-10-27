# IP Investigator

Webapp local para análise técnica e investigativa de endereços IPv4 e IPv6. O programa combina classificação local, fontes públicas/OSINT habilitadas, análise temporal, **análise em lote**, **grafos de relações em Cytoscape.js**, **casos persistidos localmente** e **relatórios PDF/JSON/Markdown com proveniência**.

> **Escopo:** ferramenta de apoio a investigação e triagem técnica. Um endereço IP não identifica, isoladamente, pessoa, autoria, dispositivo ou localização física exata. Para atribuição temporal de conexão/assinante, use registros oficiais do provedor e outros elementos de corroboração.

## Recursos principais

### Análise individual

- IPv4 e IPv6;
- resposta `Investigativo`, `Técnico` ou `Resumo`;
- data/hora do fato e fuso horário opcionais;
- porta lógica de origem e protocolo opcionais;
- conclusão investigativa ao final;
- limitações da inferência e providências sugeridas;
- referências da origem das respostas;
- download em Markdown, JSON e PDF.

### Análise em lote

- múltiplos IPv4/IPv6 em texto;
- upload de `.txt` ou `.csv`;
- reconhecimento de colunas `ip`, `address`, `endereco/endereço`, `indicator/indicador`;
- deduplicação e validação dos endereços;
- contexto temporal comum opcional;
- tabela consolidada com prefixo, ASN, organização e papel provável;
- exportação do lote em JSON e PDF;
- salvamento de todo o lote em um caso.

### Grafo investigativo com Cytoscape.js

O app constrói um grafo interativo a partir das relações efetivamente encontradas nos resultados:

```text
IP
 ├─ pertence ao prefixo ─> Prefixo BGP
 │                         └─ originado por ─> ASN
 │                                             └─ associado a ─> Organização
 ├─ PTR ─> Hostname
 ├─ geo/registro indicativo ─> País
 └─ indicador ─> Tor / VPN / proxy / hosting / sinais de reputação
```

Em análises em lote e casos, nós iguais são deduplicados. Isso permite visualizar, por exemplo, vários IPs convergindo para o mesmo ASN, prefixo ou organização.

A interface do grafo oferece:

- busca de nós;
- seleção persistente de um nó;
- layouts `Cose`, hierárquico, concêntrico, circular e grade;
- ajuste automático do enquadramento;
- legenda por tipo de entidade.

O runtime **Cytoscape.js 3.33.1** fica versionado em `assets/vendor/`, portanto o grafo não depende de CDN para renderizar. Cytoscape.js é licenciado sob MIT; veja `THIRD_PARTY_NOTICES.md`.

### Casos locais

Os casos são armazenados em SQLite:

```text
data/ip_investigator.db
```

Cada caso possui:

- nome;
- descrição;
- status;
- datas UTC de criação e atualização;
- análises vinculadas;
- JSON completo da análise;
- horário em que a análise foi salva;
- SHA-256 do bundle salvo.

É possível:

- criar e editar casos;
- salvar uma análise individual;
- salvar um lote completo;
- remover uma análise;
- excluir um caso mediante confirmação;
- exportar o caso completo em JSON;
- gerar PDF consolidado;
- visualizar o caso no grafo Cytoscape.

O banco SQLite está no `.gitignore`, para evitar commit acidental de dados de casos.

## Fontes e análise

O núcleo já suporta:

- classificação local de IPv4/IPv6 sem API;
- faixas privadas, CGNAT, loopback, link-local, multicast, documentação e outros usos especiais;
- IPv4-mapped IPv6, 6to4, Teredo e NAT64 quando aplicável;
- RDAP com bootstrap para o RIR autoritativo;
- prefixo BGP e Origin ASN via RIPEstat;
- AS Overview e validação RPKI;
- estado BGP histórico quando data/hora do fato é informada;
- DNS reverso/PTR;
- geolocalização estimada;
- relays/exit nodes Tor atuais via Onionoo;
- GreyNoise Community para IPv4;
- enriquecimento comparado via ipctl.io, GeoIPHub, ipto.to e FFraud;
- Shodan InternetDB para exposição observada em IPv4;
- PeeringDB para contexto de ASN/rede;
- AbuseIPDB e IPinfo opcionais por chave.

## Windows

### Executável standalone recomendado

Para distribuição no Windows, gere `IP-Investigator.exe` com:

```text
BUILD-WINDOWS-STANDALONE.cmd
```

O executável final incorpora Python e as dependências. Na máquina do usuário ele **não instala Python, não executa `pip` e não baixa bibliotecas para iniciar**. Dados e logs ficam em `%LOCALAPPDATA%\IP Investigator`. Consulte `WINDOWS-EXE.md`.

### Execução em modo de desenvolvimento

Pré-requisito: Python 3.11 ou superior.

1. Baixe ou clone o repositório.
2. Dê dois cliques em `run.bat`.
3. Na primeira execução de desenvolvimento, o script cria `.venv` e instala as dependências.
4. O Streamlit abre a interface local, normalmente em `http://localhost:8501`.

Execução manual:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Linux/macOS

```bash
chmod +x run.sh
./run.sh
```

ou:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Chaves opcionais

Copie `.env.example` para `.env` e preencha somente as integrações desejadas:

```env
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
IPINFO_TOKEN=
```

O app funciona sem essas chaves.

**Nunca faça commit do `.env`.** Ele já está no `.gitignore`.

## Privacidade operacional

Embora o programa rode localmente, **consultas a APIs externas revelam à respectiva fonte o endereço IP pesquisado**.

O menu lateral permite:

- ativar/desativar famílias de fontes;
- usar **Modo estritamente local**, que não envia o IP a APIs externas.

O grafo Cytoscape é carregado de uma cópia JavaScript local no próprio repositório, sem CDN.

O relatório registra as fontes efetivamente consultadas, URL, horário UTC e, quando disponível, SHA-256 da resposta normalizada.

## Fontes integradas

### RDAP

Consulta `https://rdap.org/ip/<IP>` como bootstrap para o serviço RDAP apropriado.

Documentação: https://about.rdap.org/

### RIPEstat

Usa, conforme o contexto:

- `network-info`;
- `as-overview`;
- `prefix-overview`;
- `rpki-validation`;
- `routing-status`;
- `bgp-state`;
- `maxmind-geo-lite`.

Documentação: https://stat.ripe.net/docs/data-api/ripestat-data-api

### Tor Metrics / Onionoo

Verifica relays/exit nodes atuais. Para consulta histórica, o botão **Consultar em plataformas de terceiros** gera link para ExoneraTor quando há data informada.

Documentação: https://metrics.torproject.org/onionoo.html

### GreyNoise Community

Consulta rápida para IPv4, retornando quando disponível `noise`, `RIOT`, classificação e última observação.

Documentação: https://docs.greynoise.io/reference/getcommunityip

### Enriquecimento público comparado

- ipctl.io — https://ipctl.io/docs
- GeoIPHub — https://help.geoiphub.com/docs/api/lookup
- ipto.to — https://ipto.to/docs
- FFraud — https://ffraud.com/docs
- Shodan InternetDB — https://help.shodan.io/developer-fundamentals/looking-up-ip-info
- PeeringDB — https://www.peeringdb.com/apidocs/

Indicadores de VPN/proxy/Tor/hosting/risco são tratados como sinais de inteligência e podem divergir entre fornecedores.

### AbuseIPDB (opcional)

Requer `ABUSEIPDB_API_KEY`.

Documentação: https://docs.abuseipdb.com/

### IPinfo (opcional)

Requer `IPINFO_TOKEN`.

Documentação: https://ipinfo.io/developers

## Plataformas de terceiros

O botão **Consultar em plataformas de terceiros** oferece links diretos para serviços como:

- ipctl.io;
- GeoIPHub;
- IPDebrief;
- Max Intel;
- ipto.to;
- FFraud;
- RIPEstat;
- AbuseIPDB;
- GreyNoise Visualizer;
- IPinfo;
- Tor Relay Search / ExoneraTor.

Esses serviços possuem políticas, limites e metodologias próprios.

## Relatórios PDF

O PDF é gerado localmente com ReportLab e inclui:

- identificação da consulta/caso;
- estrutura do endereço;
- prefixo/ASN/organização quando disponíveis;
- conclusão investigativa;
- limitações;
- providências sugeridas;
- scorecard de valor investigativo;
- referências e proveniência das fontes.

Em relatórios de caso, existe também uma tabela consolidada dos IPs analisados. O grafo permanece interativo no aplicativo e não é convertido automaticamente em imagem no PDF.

## Estrutura do projeto

```text
ip-investigator/
├── app.py
├── assets/
│   └── vendor/
│       ├── cytoscape.min.js
│       └── CYTOSCAPE_LICENSE.txt
├── core/
│   ├── __init__.py
│   ├── batch.py
│   ├── cases.py
│   ├── graph.py
│   ├── investigator.py
│   ├── local_analysis.py
│   ├── pdf_report.py
│   ├── report.py
│   ├── sources.py
│   └── third_party.py
├── data/
│   └── .gitkeep
├── tests/
├── .env.example
├── .gitignore
├── .streamlit/
│   └── config.toml
├── .github/workflows/tests.yml
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── requirements.txt
├── requirements-dev.txt
├── run.bat
└── run.sh
```

## Testes

```bash
pip install -r requirements-dev.txt
pytest -q
```

Os testes unitários usam o modo offline e não dependem de chamadas externas.

Atualmente cobrem:

- classificação local;
- CGNAT e IPv6;
- investigação offline;
- redação de segredos;
- parsing de lote/CSV;
- armazenamento SQLite de casos;
- construção do grafo;
- geração de PDF.

## GitHub Actions

`.github/workflows/tests.yml` executa compilação e testes em `push` e `pull_request`.

## Push para GitHub

```bash
git init
git add .
git commit -m "IP Investigator: batch, Cytoscape graph, cases and PDF reports"
git branch -M main
git remote add origin https://github.com/SEU-USUARIO/ip-investigator.git
git push -u origin main
```

## Limitações importantes

- geolocalização por IP não é GPS;
- RDAP/WHOIS descreve administração do recurso, não o usuário daquele instante;
- BGP/ASN descreve roteamento, não autoria;
- IPv4 pode ser dinâmico ou compartilhado por CGNAT;
- ausência de porta lógica pode impedir individualização em determinados cenários;
- IPv6 pode envolver múltiplos endereços simultâneos, privacy addresses e delegação dinâmica de prefixos;
- VPN, proxy, CDN, reverse proxy, cloud e Tor podem fazer o IP representar infraestrutura intermediária;
- ausência de detecção em uma base não prova ausência do fenômeno;
- dados atuais não devem ser automaticamente projetados para a data histórica do fato;
- o grafo representa relações observadas nas fontes coletadas, não causalidade, autoria ou identidade civil.

## Licenças

O projeto é MIT. Veja `LICENSE`.

Cytoscape.js é MIT. Veja `THIRD_PARTY_NOTICES.md` e `assets/vendor/CYTOSCAPE_LICENSE.txt`.

## Executável para Windows

O repositório inclui **`IP-Investigator.exe`**, um executável autoextraível para Windows x64. Basta dar dois cliques: na primeira execução ele extrai o app em `%LOCALAPPDATA%\IP Investigator\app`, instala um runtime Python privado e as dependências necessárias, inicia o servidor apenas em `127.0.0.1` e abre a interface no navegador. Não é necessário instalar Python manualmente.

A primeira execução precisa de Internet para obter o Python oficial e os pacotes Python. Depois disso, o ambiente é reutilizado localmente. Um `.env` colocado ao lado do EXE é importado automaticamente.

O workflow `.github/workflows/build-windows-exe.yml` também gera uma versão standalone com PyInstaller em runner Windows. Veja [`WINDOWS-EXE.md`](WINDOWS-EXE.md).
