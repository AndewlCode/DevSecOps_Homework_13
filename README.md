# SAST(StaticApplicationSecurityTesting)

Для анализа приложения, размещённого на [GitHub](https://github.com/anxolerd/dvpwa) был использован инструмент [Bandit](https://bandit.readthedocs.io/en/latest/index.html). Отчёт прикреплён в файле [bandit_report.txt](/reports/bandit_report.txt)

Выявлено 2 уязвимости: 1 Medium и 1 High.

## Medium - CWE-89
Первая имеет идентификатор CWE [CWE-89](https://cwe.mitre.org/data/definitions/89.html) Possible SQL injection vector through string-based query construction.
Ссылка на описание уязвимости: [B608: hardcoded_sql_expressions](https://bandit.readthedocs.io/en/1.8.3/plugins/b608_hardcoded_sql_expressions.html)

Уязвимый код содержится в строках файла dvpwa-master/sqli/dao/student.py:
```
async def create(conn: Connection, name: str):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    async with conn.cursor() as cur:
```
В проекте используется функция, которая реализует потенциально небезопасный запрос к БД.
Можно использовать альтернативный вариант функции:
~~~
async def create(conn: Connection, name: str):
    q = "INSERT INTO students (name) VALUES (%s)"
    async with conn.cursor() as cur:
        await cur.execute(q, (name,))
~~~

## High - CWE-327
Вторая уязвимость имеет идентификатор CWE [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of weak MD5 hash for security.
Ссылка на описание уязвимости: [B324: hashlib](https://bandit.readthedocs.io/en/1.8.3/plugins/b324_hashlib.html)

Уязвимый код содержится в строках файла dvpwa-master/sqli/dao/user.py
```
def check_password(self, password: str):
    return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```
В проекте используется алгоритм хеширования паролей MD5, он явялется устаревшим и не криптостойким.
Для снижения рисков ИБ необходимо использовать более устойчивые ко взлому алгоритмы шифрования.