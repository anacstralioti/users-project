<h1>Sistema em Python com Flask e SQLite</h1>

<h2>Descrição</h2>
<p>Este projeto é um sistema de autenticação de usuários desenvolvido em Python com Flask, utilizando banco de dados SQLite para armazenar informações de usuários. Entre suas funcionalidades estão cadastro, login e atualização de usuários, além do login com Google e GitHub por meio de autenticação OAuth 2.0 e redifinição de senha por meio de e-mail. As senhas são armazenadas de forma segura utilizando hashing com bcrypt e o sistema assume que o login (e-mail) fornecido no cadastro é único. O sistema suporta múltiplos idiomas, incluindo português, inglês e espanhol, com a interface de usuário podendo ser traduzida dinamicamente. Também há o controle de acesso baseado em funções (usuário administrador ou normal), onde apenas administradores podem acessar a funcionalidade de alteração de dados de usuários.</p>

<h2>Funcionalidades</h2>
<ul>
    <li><strong>Cadastro de Usuário:</strong> Permite que novos usuários se cadastrem fornecendo login (e-mail), senha e nome;</li>
    <li><strong>Login de Usuário:</strong> Permite que usuários existentes façam login;</li>
    <li><strong>Alteração de Usuário:</strong> Permite que os usuários sejam atualizados (sendo "puxados" a partir do ID) e sejam bloqueados (status alterado para inativo).</li>
    <li><strong>Recuperação de Senha:</strong> Possibilita o envio de um link de redefinição de senha para o e-mail do usuário.</li>
    <li><strong>Integração com Google e GitHub:</strong> Permite login usando contas do Google e GitHub.</li>
    <li>Suporte a Idiomas: O sistema suporta múltiplos idiomas, incluindo português, inglês e espanhol, com a interface de usuário podendo ser traduzida dinamicamente.</li>
    <li>Autenticação e Autorização: Controle de acesso baseado em funções (usuário administrador ou normal), onde apenas administradores podem acessar a funcionalidade de alteração de usuários (alterar "is.admin" em schema.sql para "1" no caso de administrador).</li></li>
</ul>

<h2>Como executar o projeto?</h2>
<ul>
    <li>Importe o projeto para o Pycharm;</li>
    <li>Certifique-se que o Python esteja na versão 3.12;</li>
    <li>No terminal execute o seguinte comando:</li>
    <ol>
        <li>pip install flask</li>
        <li>pip install flask_dance</li>
        <li>pip install flask_mail</li>
        <li>pip install flask_dance</li>
        <li>pip install flask_babel</li>
        <li>pip install bcrypt</li>
        <li>pip install itsdangerous</li>
    </ol>
</ul>

<h2>Como utilizar o projeto?</h2>
<ul>
    <li><strong>Após executar a inicialização do servidor Flask com o comando <code>python main.py</code>, o servidor será iniciado em <code>http://127.0.0.1:5000</code></strong></li>
    <li><strong>A partir daí, é possível acessar as rotas</strong>
        <ul>
            <li>Página inicial: <code>http://127.0.0.1:5000/</code></li>
            <li>IMPORTANTE: entre na rota <code>http://127.0.0.1:5000/initdb</code> para inicializar o banco de dados</li>
            <li>Cadastro de usuário: <code>http://127.0.0.1:5000/cadastro</code></li>
            <li>Login de usuário: <code>http://127.0.0.1:5000/login</code></li>
            <li>IMPORTANTE: para conseguir entrar na rota Alteração de usuário deve-se alterar o valor de "is_admin" no schema.sql de "0" para "1": <code>http://127.0.0.1:5000/alteracao</code></li>
            <li>Recuperação de senha: <code>http://127.0.0.1:5000/forgot_password</code></li>
            <li>Redefinição de senha: <code>http://127.0.0.1:5000/reset_password/<token></code></li>
            <li>Página de destino: <code>http://127.0.0.1:5000/pagina_final</code></li>
        </ul>
</ul>
