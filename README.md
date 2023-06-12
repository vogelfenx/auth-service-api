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
В дебаг режиме (для работы сначала нужно выполнить миграции - для этого следует запустить в продакшне один раз):
```docker-compose -f docker-compose.debug.yml up --build```
В продакшн режиме:
```docker-compose -f docker-compose.yml up --build```

7. Для создания супер-пользователя с ролью `admin`, использовать следующую комманду (выполнять нужно в контейнере).

   ```bash
   python manage.py createadmin
   ```

8. Работу шаблона можно проверить по http://127.0.0.1:8000/api/openapi#/
