# 🛡️ PhishGuard ML — Sistema de Detecção de URLs de Phishing Utilizando Machine Learning

## 1. Introdução

O **PhishGuard ML** é um sistema de detecção de URLs potencialmente maliciosas, desenvolvido como trabalho prático da disciplina de Inteligência Artificial e Machine Learning. O projeto tem como objetivo investigar a aplicação de técnicas de aprendizado de máquina na identificação de padrões associados a ataques de *phishing*, por meio da análise léxica e estrutural de endereços eletrônicos.

A solução utiliza o algoritmo **Random Forest** para classificar URLs com base em características extraídas de sua estrutura, sem exigir o carregamento ou a análise do conteúdo da página de destino. O sistema é composto por uma API desenvolvida em Python com Flask e uma interface web implementada em React e Vite.

## 2. Demonstração e Acesso

O sistema está disponível para acesso por meio das seguintes plataformas:

- **Front-end:** [Acessar a aplicação web](https://trabalho-pr-tico-machine-learning-p-seven.vercel.app)
- **Back-end:** [Acessar a API](https://phishguard-api-ksmh.onrender.com)

O front-end está hospedado na Vercel, enquanto a API está implantada no Render.

## 3. Objetivos

O desenvolvimento do PhishGuard ML busca aplicar conceitos de aprendizado de máquina à segurança da informação, com ênfase na análise de URLs.

Os objetivos específicos são:

- Extrair características léxicas e estruturais de URLs.
- Utilizar um modelo Random Forest para classificação automatizada.
- Disponibilizar a análise por meio de uma API REST.
- Apresentar os resultados da classificação em uma interface web.
- Fornecer informações explicativas sobre os atributos considerados relevantes para a análise.
- Demonstrar a integração entre processamento de dados, treinamento de modelos preditivos e desenvolvimento de aplicações web.

## 4. Arquitetura do Sistema

A arquitetura é organizada em dois componentes principais: o front-end, responsável pela interação com o usuário, e o back-end, responsável pelo processamento das URLs e pela inferência do modelo de aprendizado de máquina.

### 4.1. Front-end

O front-end é desenvolvido com **React** e **Vite** e hospedado na Vercel. Suas principais responsabilidades são:

- Receber a URL informada pelo usuário.
- Enviar a solicitação de análise à API.
- Exibir a classificação retornada pelo modelo.
- Apresentar informações complementares sobre os atributos identificados durante a análise.

### 4.2. Back-end

O back-end utiliza **Python** e **Flask** para disponibilizar uma API REST responsável pelo processamento das requisições. Suas funcionalidades incluem:

- Receber as URLs enviadas pelo front-end.
- Extrair os atributos utilizados pelo classificador.
- Aplicar o modelo treinado às características extraídas.
- Retornar os resultados da classificação e as informações disponibilizadas pelo sistema.

### 4.3. Modelo de aprendizado de máquina

O componente preditivo utiliza o algoritmo **Random Forest**, um método de aprendizado supervisionado baseado na combinação de múltiplas árvores de decisão.

O modelo é treinado a partir de um conjunto de dados rotulado e utiliza 22 atributos numéricos e binários para identificar padrões associados a URLs legítimas e maliciosas.

O artefato do modelo treinado é armazenado no arquivo `modelo_rf.pkl`, utilizado posteriormente durante as inferências realizadas pela API.

## 5. Metodologia de Extração de Atributos

A extração das características é implementada no módulo `extrator.py`. Nessa etapa, cada URL é convertida em um vetor numérico que representa propriedades de sua composição textual e estrutural.

Entre os atributos considerados estão:

- **Comprimento da URL:** quantidade de caracteres do endereço completo.
- **Comprimento do domínio:** quantidade de caracteres associada ao domínio.
- **Uso de endereço IP:** identificação da presença de endereços IP numéricos no lugar de nomes de domínio.
- **Características do domínio:** análise de subdomínios, pontos, hífens e outros elementos estruturais.
- **Características da extensão:** identificação de extensões de domínio consideradas suspeitas ou associadas a padrões previamente definidos.
- **Proporção de dígitos:** avaliação da presença de caracteres numéricos na URL.
- **Palavras-chave:** identificação de termos potencialmente associados a processos de autenticação, verificação de contas e operações financeiras, como `login`, `bank`, `account` e `verify`.
- **Entropia de Shannon:** medida da distribuição dos caracteres na URL, utilizada para caracterizar padrões de composição textual.

Os atributos extraídos são organizados no formato esperado pelo modelo, permitindo que URLs distintas sejam representadas por vetores de características compatíveis com o processo de classificação.

A presença isolada de um atributo suspeito não determina necessariamente que uma URL seja maliciosa. A classificação depende dos padrões aprendidos pelo modelo durante o treinamento.

## 6. Algoritmo de Classificação

O algoritmo Random Forest foi selecionado por sua capacidade de combinar diferentes árvores de decisão e identificar relações entre múltiplas características dos dados.

Durante o treinamento, o algoritmo constrói um conjunto de árvores a partir de amostras e subconjuntos de atributos. Na etapa de inferência, as previsões dessas árvores são combinadas para produzir a classificação final.

No PhishGuard ML, o processo de classificação segue as seguintes etapas:

1. Recebimento da URL informada pelo usuário.
2. Extração dos atributos léxicos e estruturais.
3. Organização das características em um vetor numérico.
4. Aplicação do modelo Random Forest previamente treinado.
5. Obtenção da classe prevista e, quando disponibilizada pelo modelo, da estimativa de probabilidade associada.
6. Retorno do resultado à interface web para apresentação ao usuário.

A interpretação de probabilidades deve considerar que elas representam estimativas do modelo e não constituem, por si só, uma garantia da legitimidade ou da segurança de um endereço.

## 7. Resultados e Avaliação

O sistema foi desenvolvido para realizar a classificação automatizada de URLs com base nas características extraídas e nos padrões identificados durante o treinamento.

A avaliação do desempenho do modelo deve considerar métricas quantitativas, como:

- **Acurácia (*Accuracy*):** proporção de classificações corretas em relação ao total de exemplos avaliados.
- **Precisão (*Precision*):** proporção de URLs classificadas como maliciosas que realmente pertencem à classe maliciosa.
- **Revocação (*Recall*):** proporção de URLs maliciosas corretamente identificadas pelo modelo.
- **F1-score:** média harmônica entre precisão e revocação.
- **Matriz de confusão:** representação dos acertos e erros de classificação em cada classe.

O modelo foi treinado e validado utilizando uma amostra robusta de **9.000 tuplas reais** extraídas de bases públicas do Kaggle, submetidas a um pipeline rigoroso de engenharia de *features* e validação estatística.

* **Validação Cruzada Estratifizada (5-Folds):** Acurácia Média de **85.83%** ($\pm 0.0032$)
* **Métricas no Conjunto de Teste Independente (20%):**
  * **Acurácia (Accuracy):** 85.80%
  * **Precisão (Precision):** 88.07%
  * **Revocação (Recall):** 82.82%
  * **F1-Score:** 85.36%
  * **ROC-AUC Score:** **0.9460** (Excelente capacidade de discriminação)

### 10 Atributos Mais Importantes (Feature Importances)
O Random Forest avaliou e pesou os atributos estruturais extraídos das URLs da seguinte forma:
1. `tem_extensao_sensivel` (7.86%)
2. `entropia_dominio` (7.71%)
3. `qtd_iguais` (7.61%)
4. `entropia_url` (7.08%)
5. `tamanho_caminho` (6.87%)
6. `proporcao_digitos` (6.43%)
7. `tamanho_dominio` (6.42%)
8. `tamanho_url` (6.13%)
9. `qtd_digitos_dominio` (5.68%)
10. `qtd_hifens_dominio` (5.62%)

Essas métricas permitem avaliar tanto a capacidade geral de classificação quanto a ocorrência de falsos positivos e falsos negativos.

## 8. Limitações

O PhishGuard ML realiza a classificação com base em características léxicas e estruturais da URL. Dessa forma, a análise não verifica diretamente o conteúdo da página, o comportamento de scripts, a validade de certificados digitais, a reputação atual do domínio ou a presença de conteúdo malicioso no destino.

Consequentemente, URLs legítimas podem ser classificadas incorretamente como suspeitas, assim como URLs maliciosas podem não ser identificadas. Alterações nas estratégias utilizadas por atacantes e o surgimento de novos domínios também podem reduzir o desempenho do modelo ao longo do tempo.

O sistema deve ser compreendido como um mecanismo auxiliar de análise, e não como uma garantia definitiva de segurança.

## 9. Tecnologias Utilizadas

| Tecnologia | Aplicação |
|---|---|
| Python | Linguagem principal do back-end e do processamento dos dados |
| Flask | Desenvolvimento da API REST |
| Scikit-learn | Implementação e utilização do modelo Random Forest |
| NumPy | Operações numéricas |
| Pandas | Manipulação e análise de dados |
| Joblib | Serialização e carregamento do modelo treinado |
| React | Desenvolvimento da interface web |
| Vite | Ferramenta de desenvolvimento e compilação do front-end |
| Vercel | Hospedagem do front-end |
| Render | Hospedagem da API |

## 10. Execução Local

### 10.1. Pré-requisitos

Para executar o projeto localmente, é necessário ter instalado:

- Python em uma versão compatível com as dependências do projeto.
- Node.js e npm.
- Git.

### 10.2. Clonagem do repositório

```bash
git clone https://github.com/lauraevelyn2004/TRABALHO-PR-TICO-MACHINE-LEARNING-PYTHON.git

cd TRABALHO-PR-TICO-MACHINE-LEARNING-PYTHON
```

### 10.3. Configuração do back-end

Acesse o diretório do back-end, instale as dependências e execute a aplicação:

```bash
cd backend

pip install -r requirements.txt

python app.py
```

Por padrão, a API poderá ser acessada em:

`http://localhost:5000`

A inicialização depende da configuração definida no arquivo `app.py` e da disponibilidade dos arquivos necessários ao modelo.

### 10.4. Configuração do front-end

Em outro terminal, retorne à raiz do projeto e acesse o diretório do front-end:

```bash
cd frontend

npm install

npm run dev
```

O Vite disponibilizará o endereço local da aplicação, normalmente:

`http://localhost:5173`

Caso necessário, a URL da API deverá ser configurada de acordo com as variáveis de ambiente e as definições utilizadas pelo front-end.

## 11. Estrutura do Projeto

A organização geral do repositório é apresentada a seguir:

```text
TRABALHO-PR-TICO-MACHINE-LEARNING-PYTHON/
├── backend/
│   ├── app.py
│   ├── extrator.py
│   ├── treinar_modelo.py
│   ├── requirements.txt
│   ├── runtime.txt
│   └── modelo_rf.pkl
│
├── frontend/
│   ├── package.json
│   ├── index.html
│   ├── src/
│   └── ...
│
└── README.md
```

A estrutura apresentada é ilustrativa e pode variar conforme os arquivos efetivamente presentes no repositório.

## 12. Considerações Finais

O desenvolvimento do PhishGuard ML possibilitou a aplicação prática de conceitos de aprendizado de máquina, engenharia de atributos, classificação supervisionada e desenvolvimento de APIs.

A integração entre o modelo preditivo, o back-end em Flask e a interface web demonstra uma abordagem para disponibilizar técnicas de análise automatizada de URLs em uma aplicação acessível ao usuário.

Como possibilidades de evolução, destacam-se a ampliação e atualização do conjunto de dados, a realização de avaliações experimentais mais abrangentes, a análise de importância dos atributos, a comparação com outros algoritmos de classificação e a incorporação de fontes complementares de informação sobre domínios.

## 13. Autoria

**Desenvolvido por:** Laura Evelyn Neves Oliveira e Amanda Dias Alves Ferreira

**Finalidade:** Trabalho prático da disciplina de Inteligência Artificial prof: Matheus Eloy Franco
