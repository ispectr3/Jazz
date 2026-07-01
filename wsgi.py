from dotenv import load_dotenv
load_dotenv() # Carrega as chaves do arquivo .env

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
