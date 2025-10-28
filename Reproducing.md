Este guia mostra como **reproduzir 100%** do que está neste repositório, de forma mínima e confiável.

## Opção A) Rodar tudo localmente (venv + Jupyter + Python)

### 0) Pré-requisitos
- Python 3.10+ (testado em macOS/Apple Silicon)
- (Opcional para DFIR real) Volatility 3 instalado e um dump de memória do lab Reveal

### 1) Clonar o repositório
```bash
git clone https://github.com/The-Black-Needles/case02-reveal-dfir-volatility3-aml.git
cd case02-reveal-dfir-volatility3-aml
```
### 2) Criar ambiente e instalar dependências

```bash 
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

