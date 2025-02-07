import csv
from app import app, db, Resource  # Ensure these are correctly imported from your app.py

def import_resources(csv_filename):
    with app.app_context():
        with open(csv_filename, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            print("CSV Headers:", reader.fieldnames)
            for row in reader:
                name_raw = row.get('Name')
                name = name_raw.strip() if name_raw is not None else ""
                print("Row 'Name':", repr(name))
                
                if not name:
                    print("Skipping row with missing name:", row)
                    continue

                resource = Resource(
                    name=name,
                    category=row.get('Category'),
                    population_served=row.get('Population Served'),
                    location=row.get('Location'),
                    hours=row.get('Hours'),
                    contact_information=row.get('Contact Information'),
                    eligibility=row.get('Eligibility'),
                    details=row.get('Details')
                )
                db.session.add(resource)
            db.session.commit()
        print("Import complete!")

if __name__ == '__main__':
    import_resources('master_resources.csv')