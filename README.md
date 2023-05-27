# Auth_API
Authentication Service repository
1. Переместиться в папку проекта
```cd <project_folder>```

2. Установить виртуальную среду
```python.exe -m venv .venv```

3. Активировать виртуальную среду
```.\.venv\Scripts\Activate.ps1```

4. Установить зависимости для проекта
```pip install -r .\app\src\requirements.txt```

5. Установить дополнительные зависимости для разработки проекта
```pip install -r .\app\src\requirements.dev.txt```

6. Запустить проект
```docker-compose -f docker-compose.debug.yml up --build```

7. Работу шаблона можно проерить по http://127.0.0.1:8000/api/openapi#/