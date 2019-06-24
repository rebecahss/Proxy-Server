# Proxy-Server
Trabalho da disciplina Transmissão de Dados 2019/1 - Servidor Proxy Web com filtro de conteúdo

Francisco Matheus
Rebeca Helen

Para o correto funcionamento do servidor proxy, se certifique de que todas os arquivos estão na mesma pasta do programa, são os eles:
    -blacklist;
    -whitelist;
    -deny_terms;
    -logs;
    -deny_terms_page;
    -blacklistpage;

Além disso, os termos inseridos nos arquivos blacklist, whitelist e deny_terms devem sempre ser inseridos em uma nova linha, nuca colocar mais de um termo ou url na mesma linha, pois pode acarretar em um mal fincionamento da busca pelo mesmo.
Para funcionamento do proxy, é necessário configurar o navegador a ser monitorado para que faça as requisições no IP 127.0.0.1 e porta:8088, só assim as requisições serão encaminhadas ao servidor proxy.

A compilação deve ser feita com Python 3
