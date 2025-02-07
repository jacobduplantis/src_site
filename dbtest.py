from app import app, db, Resource
with app.app_context():
    resources = Resource.query.all()
    print(type(resources[45]))
    