# voter_analytics/models.py

from django.db import models
import csv
import os
from django.conf import settings
from datetime import datetime
from django.db.models import Count

class Voter(models.Model):
    """
    Model to represent a registered voter in Newton, MA.
    """
    # Personal Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    street_number = models.CharField(max_length=10)
    street_name = models.CharField(max_length=100)
    apartment_number = models.CharField(max_length=10, blank=True, null=True)
    zip_code = models.CharField(max_length=10)
    date_of_birth = models.DateField()
    date_of_registration = models.DateField()
    party_affiliation = models.CharField(max_length=100)
    precinct_number = models.CharField(max_length=10)

    # Voting Participation
    v20state = models.BooleanField()
    v21town = models.BooleanField()
    v21primary = models.BooleanField()
    v22general = models.BooleanField()
    v23town = models.BooleanField()
    voter_score = models.IntegerField()

    def __str__(self):
        """String representation of the Voter."""
        return f"{self.first_name} {self.last_name} ({self.party_affiliation})"

    @property
    def full_address(self):
        """Returns the full street address."""
        address = f"{self.street_number} {self.street_name}"
        if self.apartment_number:
            address += f", Apt {self.apartment_number}"
        address += f", Newton, MA {self.zip_code}"
        return address

def load_data():
    """
    Function to load voter data from 'newton_voters.csv' into the database.
    """
    # Path to the CSV file
    file_path = os.path.join(settings.BASE_DIR, 'data', 'newton_voters.csv')

    # Delete existing records to avoid duplicates
    Voter.objects.all().delete()

    # Open the CSV file
    with open(file_path, mode='r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        total_records = 0
        for row in reader:
            try:
                # Convert date strings to date objects
                dob = datetime.strptime(row['Date of Birth'], '%Y-%m-%d').date()
                registration_date = datetime.strptime(row['Date of Registration'], '%Y-%m-%d').date()

                # Create a Voter instance
                voter = Voter(
                    first_name=row['First Name'].strip(),
                    last_name=row['Last Name'].strip(),
                    street_number=row['Residential Address - Street Number'].strip(),
                    street_name=row['Residential Address - Street Name'].strip(),
                    apartment_number=row['Residential Address - Apartment Number'].strip() or None,
                    zip_code=row['Residential Address - Zip Code'].strip(),
                    date_of_birth=dob,
                    date_of_registration=registration_date,
                    party_affiliation=row['Party Affiliation'].strip(),
                    precinct_number=row['Precinct Number'].strip(),
                    v20state=row['v20state'].strip().upper() == 'TRUE',
                    v21town=row['v21town'].strip().upper() == 'TRUE',
                    v21primary=row['v21primary'].strip().upper() == 'TRUE',
                    v22general=row['v22general'].strip().upper() == 'TRUE',
                    v23town=row['v23town'].strip().upper() == 'TRUE',
                    voter_score=int(row['voter_score'].strip()),
                )
                voter.save()
                total_records += 1
            except Exception as e:
                print(f"Error processing row {row}: {e}")

    print(f"Successfully loaded {total_records} voter records.")
