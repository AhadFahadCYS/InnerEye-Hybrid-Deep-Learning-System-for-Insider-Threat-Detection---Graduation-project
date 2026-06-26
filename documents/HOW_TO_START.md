python version:
https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe

## 2. تثبيت المتطلبات

```bash
py -3.11 -m venv .venv311
.\.venv311\Scripts\activate
pip install -r requirements.txt
```

## 3. تشغيل التطبيق (Flask)

```bash`
python app\app.py
```

افتح المتصفح على **http://localhost:5000**.

---`

## 4. اختبار

ارفع `test_users.csv` ثم اضغط **Run Detection**. المستخدم `USR0005` يجب أن يظهر **HIGH risk**.

> ملاحظة: إذا كان لديك مجلد `.venv` قديم، احذفه لأن Python 3.14 قد لا يكون متوافقًا مع TensorFlow.

