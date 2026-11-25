"""Tests for the Employee and Device storage module."""

import os
import sqlite3
import tempfile

import pytest

from src.models import Employee, Device
from src import storage


class TestEmployeeStorage:
    """Tests for employee storage and retrieval."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_store_employee_returns_employee_id(self):
        """Verify store_employee returns the employee ID."""
        employee = Employee(
            employee_id="EMP-TEST-001",
            full_name="Test User",
            email="test@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=25,
            status="ACTIVE"
        )

        emp_id = storage.store_employee(employee, self.test_db_path)
        assert emp_id == "EMP-TEST-001"

    def test_get_employees_retrieves_all(self):
        """Verify get_employees returns all employees."""
        emp1 = Employee(
            employee_id="EMP-001",
            full_name="Alice Smith",
            email="alice@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        emp2 = Employee(
            employee_id="EMP-002",
            full_name="Bob Jones",
            email="bob@company.com",
            department="Payments & Clearing",
            role="Analyst",
            employment_type="Contingent",
            work_mode="Remote",
            city="London",
            country="UK",
            training_completed=False,
            risk_score=30,
            status="ACTIVE"
        )

        storage.store_employee(emp1, self.test_db_path)
        storage.store_employee(emp2, self.test_db_path)

        employees = storage.get_employees(self.test_db_path)
        assert len(employees) == 2

        # Check ordering by full_name
        assert employees[0].full_name == "Alice Smith"
        assert employees[1].full_name == "Bob Jones"

    def test_get_employee_by_id(self):
        """Verify get_employee retrieves a specific employee."""
        employee = Employee(
            employee_id="EMP-003",
            full_name="Carol White",
            email="carol@company.com",
            department="Fraud Operations",
            role="Investigator",
            employment_type="Employee",
            work_mode="Office",
            city="Paris",
            country="France",
            training_completed=True,
            risk_score=15,
            status="ACTIVE"
        )

        storage.store_employee(employee, self.test_db_path)
        retrieved = storage.get_employee("EMP-003", self.test_db_path)

        assert retrieved is not None
        assert retrieved.employee_id == "EMP-003"
        assert retrieved.full_name == "Carol White"
        assert retrieved.email == "carol@company.com"
        assert retrieved.department == "Fraud Operations"
        assert retrieved.employment_type == "Employee"
        assert retrieved.work_mode == "Office"
        assert retrieved.city == "Paris"
        assert retrieved.country == "France"
        assert retrieved.training_completed is True
        assert retrieved.risk_score == 15
        assert retrieved.status == "ACTIVE"

    def test_get_employee_returns_none_for_nonexistent(self):
        """Verify get_employee returns None for non-existent ID."""
        result = storage.get_employee("EMP-NONEXISTENT", self.test_db_path)
        assert result is None

    def test_employee_persists_across_calls(self):
        """Verify employee data persists across multiple calls."""
        employee = Employee(
            employee_id="EMP-PERSIST",
            full_name="Persist Test",
            email="persist@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="Tokyo",
            country="Japan",
            training_completed=True,
            risk_score=5,
            status="ACTIVE"
        )

        storage.store_employee(employee, self.test_db_path)

        # Retrieve multiple times
        emp1 = storage.get_employee("EMP-PERSIST", self.test_db_path)
        emp2 = storage.get_employee("EMP-PERSIST", self.test_db_path)

        assert emp1 is not None
        assert emp2 is not None
        assert emp1.full_name == emp2.full_name == "Persist Test"


class TestDeviceStorage:
    """Tests for device storage and retrieval."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_store_device_returns_device_id(self):
        """Verify store_device returns the device ID."""
        device = Device(
            device_id="DEV-TEST-001",
            hostname="FIN-MBP-1234",
            employee_id="EMP-001",
            employee_name="Test User",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.1",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )

        dev_id = storage.store_device(device, self.test_db_path)
        assert dev_id == "DEV-TEST-001"

    def test_get_devices_retrieves_all_with_employee_join(self):
        """Verify get_devices returns all devices with employee data."""
        # First create an employee
        employee = Employee(
            employee_id="EMP-DEV-001",
            full_name="Device Owner",
            email="owner@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        # Create devices
        dev1 = Device(
            device_id="DEV-001",
            hostname="FIN-MBP-1111",
            employee_id="EMP-DEV-001",
            employee_name="Device Owner",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.1",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )
        dev2 = Device(
            device_id="DEV-002",
            hostname="PAY-WIN-2222",
            employee_id="EMP-DEV-001",
            employee_name="Device Owner",
            device_type="Workstation",
            os_name="Windows 11 24H2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.2",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Exceptions",
            edr_status="Outdated Agent",
            isolated=False
        )

        storage.store_device(dev1, self.test_db_path)
        storage.store_device(dev2, self.test_db_path)

        devices = storage.get_devices(self.test_db_path)
        assert len(devices) == 2

        # Check ordering by hostname
        assert devices[0].hostname == "FIN-MBP-1111"
        assert devices[1].hostname == "PAY-WIN-2222"

        # Check employee join data is available
        assert devices[0].employee_name == "Device Owner"
        assert devices[1].employee_id == "EMP-DEV-001"

    def test_get_device_by_id(self):
        """Verify get_device retrieves a specific device with employee join."""
        employee = Employee(
            employee_id="EMP-DEV-002",
            full_name="Another Owner",
            email="another@company.com",
            department="Payments & Clearing",
            role="Analyst",
            employment_type="Contingent",
            work_mode="Remote",
            city="London",
            country="UK",
            training_completed=False,
            risk_score=20,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-003",
            hostname="SEC-LNX-3333",
            employee_id="EMP-DEV-002",
            employee_name="Another Owner",
            device_type="Server",
            os_name="Ubuntu 24.04 LTS",
            employment_type="Contingent",
            work_mode="Remote",
            ip_address="10.0.0.3",
            city="London",
            country="UK",
            lat=51.5074,
            lon=-0.1278,
            compliance_status="Non-Compliant",
            edr_status="Tamper Alert",
            isolated=True
        )
        storage.store_device(device, self.test_db_path)

        retrieved = storage.get_device("DEV-003", self.test_db_path)

        assert retrieved is not None
        assert retrieved.device_id == "DEV-003"
        assert retrieved.hostname == "SEC-LNX-3333"
        assert retrieved.employee_id == "EMP-DEV-002"
        assert retrieved.employee_name == "Another Owner"
        assert retrieved.device_type == "Server"
        assert retrieved.os_name == "Ubuntu 24.04 LTS"
        assert retrieved.compliance_status == "Non-Compliant"
        assert retrieved.edr_status == "Tamper Alert"
        assert retrieved.isolated is True

    def test_get_device_returns_none_for_nonexistent(self):
        """Verify get_device returns None for non-existent ID."""
        result = storage.get_device("DEV-NONEXISTENT", self.test_db_path)
        assert result is None


class TestDeviceIsolation:
    """Tests for device isolation operations."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_update_device_isolation_to_true(self):
        """Verify update_device_isolation sets isolated=True."""
        employee = Employee(
            employee_id="EMP-ISO-001",
            full_name="Isolation Test",
            email="iso@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-ISO-001",
            hostname="FIN-MBP-ISO1",
            employee_id="EMP-ISO-001",
            employee_name="Isolation Test",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.1",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )
        storage.store_device(device, self.test_db_path)

        # Isolate the device
        result = storage.update_device_isolation(
            "DEV-ISO-001", True, "analyst1", "Malware detected", self.test_db_path
        )

        assert result is True

        # Verify isolation status
        retrieved = storage.get_device("DEV-ISO-001", self.test_db_path)
        assert retrieved.isolated is True

    def test_update_device_isolation_to_false(self):
        """Verify update_device_isolation sets isolated=False."""
        employee = Employee(
            employee_id="EMP-ISO-002",
            full_name="Unisolation Test",
            email="uniso@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-ISO-002",
            hostname="FIN-MBP-ISO2",
            employee_id="EMP-ISO-002",
            employee_name="Unisolation Test",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.2",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=True  # Start isolated
        )
        storage.store_device(device, self.test_db_path)

        # Unisolate the device
        result = storage.update_device_isolation(
            "DEV-ISO-002", False, "analyst1", "Remediation complete", self.test_db_path
        )

        assert result is True

        # Verify isolation status
        retrieved = storage.get_device("DEV-ISO-002", self.test_db_path)
        assert retrieved.isolated is False

    def test_update_device_isolation_returns_false_for_nonexistent(self):
        """Verify update_device_isolation returns False for non-existent device."""
        result = storage.update_device_isolation(
            "DEV-NONEXISTENT", True, "analyst1", "Test", self.test_db_path
        )
        assert result is False

    def test_isolate_device_convenience_function(self):
        """Verify isolate_device convenience function works."""
        employee = Employee(
            employee_id="EMP-ISO-003",
            full_name="Convenience Test",
            email="conv@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-ISO-003",
            hostname="FIN-MBP-ISO3",
            employee_id="EMP-ISO-003",
            employee_name="Convenience Test",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.3",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )
        storage.store_device(device, self.test_db_path)

        result = storage.isolate_device("DEV-ISO-003", "Suspicious activity", "analyst1", self.test_db_path)
        assert result is True

        retrieved = storage.get_device("DEV-ISO-003", self.test_db_path)
        assert retrieved.isolated is True

    def test_unisolate_device_convenience_function(self):
        """Verify unisolate_device convenience function works."""
        employee = Employee(
            employee_id="EMP-ISO-004",
            full_name="Unisolate Test",
            email="unisolate@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-ISO-004",
            hostname="FIN-MBP-ISO4",
            employee_id="EMP-ISO-004",
            employee_name="Unisolate Test",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.4",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=True
        )
        storage.store_device(device, self.test_db_path)

        result = storage.unisolate_device("DEV-ISO-004", "analyst1", self.test_db_path)
        assert result is True

        retrieved = storage.get_device("DEV-ISO-004", self.test_db_path)
        assert retrieved.isolated is False

    def test_isolation_logs_audit_entry(self):
        """Verify isolation actions are logged to audit_log."""
        employee = Employee(
            employee_id="EMP-AUDIT-001",
            full_name="Audit Test",
            email="audit@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        storage.store_employee(employee, self.test_db_path)

        device = Device(
            device_id="DEV-AUDIT-001",
            hostname="FIN-MBP-AUDIT",
            employee_id="EMP-AUDIT-001",
            employee_name="Audit Test",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.1",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )
        storage.store_device(device, self.test_db_path)

        # Isolate
        storage.isolate_device("DEV-AUDIT-001", "Test isolation", "analyst1", self.test_db_path)

        # Check audit log
        audit = storage.get_audit_log(limit=10, db_path=self.test_db_path)
        assert len(audit) >= 1
        # Most recent entry should be the isolation
        isolate_entry = audit[0]
        assert isolate_entry['action_type'] == 'isolate_device'
        assert isolate_entry['target'] == 'DEV-AUDIT-001'
        assert isolate_entry['performed_by'] == 'analyst1'
        assert 'Test isolation' in isolate_entry['reason']


class TestFleetPosture:
    """Tests for get_fleet_posture function."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_get_fleet_posture_empty_database(self):
        """Verify get_fleet_posture works on empty database."""
        posture = storage.get_fleet_posture(self.test_db_path)

        assert 'compliance_breakdown' in posture
        assert 'fleet_kpis' in posture
        assert 'geo_nodes' in posture
        assert 'devices' in posture

        assert posture['compliance_breakdown']['Compliant'] == 0
        assert posture['compliance_breakdown']['Exceptions'] == 0
        assert posture['compliance_breakdown']['Non-Compliant'] == 0
        assert posture['fleet_kpis']['total_devices'] == 0
        assert posture['devices'] == []

    def test_get_fleet_posture_with_data(self):
        """Verify get_fleet_posture returns correct data with employees and devices."""
        # Create employees
        emp1 = Employee(
            employee_id="EMP-FP-001",
            full_name="Employee One",
            email="emp1@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=10,
            status="ACTIVE"
        )
        emp2 = Employee(
            employee_id="EMP-FP-002",
            full_name="Employee Two",
            email="emp2@company.com",
            department="Payments & Clearing",
            role="Analyst",
            employment_type="Contingent",
            work_mode="Remote",
            city="London",
            country="UK",
            training_completed=False,
            risk_score=20,
            status="ACTIVE"
        )
        emp3 = Employee(
            employee_id="EMP-FP-003",
            full_name="Employee Three",
            email="emp3@company.com",
            department="Fraud Operations",
            role="Investigator",
            employment_type="Employee",
            work_mode="Remote",
            city="Tokyo",
            country="Japan",
            training_completed=True,
            risk_score=15,
            status="ACTIVE"
        )
        storage.store_employee(emp1, self.test_db_path)
        storage.store_employee(emp2, self.test_db_path)
        storage.store_employee(emp3, self.test_db_path)

        # Create devices
        dev1 = Device(
            device_id="DEV-FP-001",
            hostname="FIN-MBP-1001",
            employee_id="EMP-FP-001",
            employee_name="Employee One",
            device_type="Laptop",
            os_name="macOS 15.2",
            employment_type="Employee",
            work_mode="Office",
            ip_address="10.0.0.1",
            city="New York",
            country="USA",
            lat=40.7128,
            lon=-74.0060,
            compliance_status="Compliant",
            edr_status="Protected",
            isolated=False
        )
        dev2 = Device(
            device_id="DEV-FP-002",
            hostname="PAY-WIN-1002",
            employee_id="EMP-FP-002",
            employee_name="Employee Two",
            device_type="Workstation",
            os_name="Windows 11 24H2",
            employment_type="Contingent",
            work_mode="Remote",
            ip_address="10.0.0.2",
            city="London",
            country="UK",
            lat=51.5074,
            lon=-0.1278,
            compliance_status="Exceptions",
            edr_status="Outdated Agent",
            isolated=False
        )
        dev3 = Device(
            device_id="DEV-FP-003",
            hostname="SEC-LNX-1003",
            employee_id="EMP-FP-003",
            employee_name="Employee Three",
            device_type="Server",
            os_name="Ubuntu 24.04 LTS",
            employment_type="Employee",
            work_mode="Remote",
            ip_address="10.0.0.3",
            city="Tokyo",
            country="Japan",
            lat=35.6762,
            lon=139.6503,
            compliance_status="Non-Compliant",
            edr_status="Tamper Alert",
            isolated=True
        )
        storage.store_device(dev1, self.test_db_path)
        storage.store_device(dev2, self.test_db_path)
        storage.store_device(dev3, self.test_db_path)

        posture = storage.get_fleet_posture(self.test_db_path)

        # Check compliance breakdown
        cb = posture['compliance_breakdown']
        assert cb['Compliant'] == 1
        assert cb['Exceptions'] == 1
        assert cb['Non-Compliant'] == 1
        assert 'percentages' in cb
        assert cb['percentages']['Compliant'] == 33.3
        assert cb['percentages']['Exceptions'] == 33.3
        assert cb['percentages']['Non-Compliant'] == 33.3

        # Check fleet KPIs
        kpis = posture['fleet_kpis']
        assert kpis['employee_office'] == 1
        assert kpis['contingent_remote'] == 1
        assert kpis['employee_remote'] == 1
        assert kpis['contingent_office'] == 0
        assert kpis['total_devices'] == 3
        assert kpis['training_completion_pct'] == 66.7  # 2 out of 3 completed

        # Check geo nodes
        geo = posture['geo_nodes']
        assert len(geo) == 3
        cities = {g['city'] for g in geo}
        assert cities == {'New York', 'London', 'Tokyo'}

        # Check devices list
        devices = posture['devices']
        assert len(devices) == 3
        assert devices[0]['device_id'] == 'DEV-FP-001'
        assert devices[2]['isolated'] is True


class TestSeedRealisticEnvironment:
    """Tests for seed_realistic_environment function."""

    def setup_method(self):
        """Set up test database before each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.temp_dir, 'test_siem.db')
        storage.init_db(self.test_db_path)

    def teardown_method(self):
        """Clean up test database after each test."""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_seed_creates_75_employees_and_110_devices(self):
        """Verify seed creates correct number of employees and devices."""
        emp_count, dev_count = storage.seed_realistic_environment(self.test_db_path, reset=True)

        assert emp_count == 75
        assert dev_count == 110

        # Verify actual counts in database
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM employees')
            assert cursor.fetchone()[0] == 75
            cursor.execute('SELECT COUNT(*) FROM devices')
            assert cursor.fetchone()[0] == 110

    def test_seed_employee_data_quality(self):
        """Verify seeded employees have correct data quality."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        employees = storage.get_employees(self.test_db_path)
        assert len(employees) == 75

        # Check all required fields are populated
        for emp in employees:
            assert emp.employee_id is not None
            assert emp.full_name is not None
            assert emp.email is not None
            assert emp.department in [
                "Core Banking", "Payments & Clearing", "Fraud Operations",
                "DevSecOps", "Cloud Infrastructure", "Mobile Engineering",
                "Risk & Compliance", "Treasury"
            ]
            assert emp.role is not None
            assert emp.employment_type in ["Employee", "Contingent"]
            assert emp.work_mode in ["Office", "Remote"]
            assert emp.city is not None
            assert emp.country is not None
            assert isinstance(emp.training_completed, bool)
            assert 0 <= emp.risk_score <= 100
            assert emp.status in ["ACTIVE", "FROZEN"]

    def test_seed_device_data_quality(self):
        """Verify seeded devices have correct data quality."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        devices = storage.get_devices(self.test_db_path)
        assert len(devices) == 110

        for dev in devices:
            assert dev.device_id is not None
            assert dev.hostname is not None
            assert dev.employee_id is not None
            assert dev.employee_name is not None
            assert dev.device_type in ["Laptop", "Workstation", "Server", "Mobile"]
            assert dev.os_name in ["macOS 15.2", "Windows 11 24H2", "Ubuntu 24.04 LTS", "iOS 18.1"]
            assert dev.employment_type in ["Employee", "Contingent"]
            assert dev.work_mode in ["Office", "Remote"]
            assert dev.ip_address is not None
            assert dev.city is not None
            assert dev.country is not None
            assert isinstance(dev.lat, float)
            assert isinstance(dev.lon, float)
            assert dev.compliance_status in ["Compliant", "Exceptions", "Non-Compliant"]
            assert dev.edr_status in ["Protected", "Outdated Agent", "Tamper Alert"]
            assert isinstance(dev.isolated, bool)

    def test_seed_hostname_formats(self):
        """Verify seeded devices have realistic hostname formats."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        devices = storage.get_devices(self.test_db_path)
        hostnames = [d.hostname for d in devices]

        # Check for expected prefix patterns
        fin_count = sum(1 for h in hostnames if h.startswith("FIN-"))
        pay_count = sum(1 for h in hostnames if h.startswith("PAY-"))
        sec_count = sum(1 for h in hostnames if h.startswith("SEC-"))
        ops_count = sum(1 for h in hostnames if h.startswith("OPS-"))
        mob_count = sum(1 for h in hostnames if h.startswith("MOB-"))
        risk_count = sum(1 for h in hostnames if h.startswith("RISK-"))
        trs_count = sum(1 for h in hostnames if h.startswith("TRS-"))

        # Should have devices with department-appropriate prefixes
        assert fin_count > 0
        assert pay_count > 0
        assert sec_count > 0
        assert ops_count > 0

    def test_seed_training_completion_rate(self):
        """Verify ~75% training completion rate."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        employees = storage.get_employees(self.test_db_path)
        completed = sum(1 for e in employees if e.training_completed)
        rate = completed / len(employees)

        # Allow some tolerance around 75%
        assert 0.70 <= rate <= 0.80

    def test_seed_compliance_ratios(self):
        """Verify compliance ratios: 58% Compliant, 24% Exceptions, 18% Non-Compliant."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        devices = storage.get_devices(self.test_db_path)
        total = len(devices)

        compliant = sum(1 for d in devices if d.compliance_status == "Compliant")
        exceptions = sum(1 for d in devices if d.compliance_status == "Exceptions")
        non_compliant = sum(1 for d in devices if d.compliance_status == "Non-Compliant")

        # Allow tolerance around expected ratios
        assert abs(compliant / total - 0.58) < 0.08
        assert abs(exceptions / total - 0.24) < 0.08
        assert abs(non_compliant / total - 0.18) < 0.08

    def test_seed_distribution_across_employment_workmode(self):
        """Verify distribution across Employee/Contingent and Office/Remote."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        employees = storage.get_employees(self.test_db_path)

        emp_office = sum(1 for e in employees if e.employment_type == "Employee" and e.work_mode == "Office")
        emp_remote = sum(1 for e in employees if e.employment_type == "Employee" and e.work_mode == "Remote")
        cont_office = sum(1 for e in employees if e.employment_type == "Contingent" and e.work_mode == "Office")
        cont_remote = sum(1 for e in employees if e.employment_type == "Contingent" and e.work_mode == "Remote")

        # Should have all four categories represented
        assert emp_office > 0
        assert emp_remote > 0
        assert cont_office > 0
        assert cont_remote > 0

        # Total should be 75
        assert emp_office + emp_remote + cont_office + cont_remote == 75

    def test_seed_is_idempotent(self):
        """Verify seed can be called multiple times without duplicating."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)
        count1 = storage.seed_realistic_environment(self.test_db_path, reset=False)

        assert count1 == (75, 110)

        # Verify no duplicates
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM employees')
            assert cursor.fetchone()[0] == 75
            cursor.execute('SELECT COUNT(*) FROM devices')
            assert cursor.fetchone()[0] == 110

    def test_seed_with_reset_clears_existing(self):
        """Verify seed with reset=True clears existing data."""
        storage.seed_realistic_environment(self.test_db_path, reset=True)

        # Add some extra data manually
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO employees (employee_id, full_name, email, department, role,
                    employment_type, work_mode, city, country, training_completed, risk_score, status)
                VALUES ('EMP-EXTRA', 'Extra User', 'extra@test.com', 'Core Banking', 'Engineer',
                    'Employee', 'Office', 'Test City', 'Test Country', 1, 10, 'ACTIVE')
            ''')
            conn.commit()

        # Reset and re-seed
        count2 = storage.seed_realistic_environment(self.test_db_path, reset=True)

        assert count2 == (75, 110)

        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM employees')
            assert cursor.fetchone()[0] == 75


if __name__ == "__main__":
    pytest.main([__file__, "-v"])