"""Tests for Employee and Device dataclasses in models.py."""

import pytest
from src.models import Employee, Device


class TestEmployee:
    """Tests for the Employee dataclass."""

    def test_employee_creation(self):
        """Test creating an Employee instance with all required fields."""
        employee = Employee(
            employee_id="EMP-001",
            full_name="John Doe",
            email="john.doe@company.com",
            department="Core Banking",
            role="Senior Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=25,
            status="ACTIVE"
        )

        assert employee.employee_id == "EMP-001"
        assert employee.full_name == "John Doe"
        assert employee.email == "john.doe@company.com"
        assert employee.department == "Core Banking"
        assert employee.role == "Senior Engineer"
        assert employee.employment_type == "Employee"
        assert employee.work_mode == "Office"
        assert employee.city == "New York"
        assert employee.country == "USA"
        assert employee.training_completed is True
        assert employee.risk_score == 25
        assert employee.status == "ACTIVE"

    def test_employee_department_values(self):
        """Test all valid department values."""
        departments = [
            "Core Banking",
            "Payments & Clearing",
            "Fraud Operations",
            "DevSecOps",
            "Cloud Infrastructure",
            "Mobile Engineering",
            "Risk & Compliance",
            "Treasury"
        ]

        for dept in departments:
            employee = Employee(
                employee_id="EMP-001",
                full_name="Test User",
                email="test@company.com",
                department=dept,
                role="Engineer",
                employment_type="Employee",
                work_mode="Office",
                city="New York",
                country="USA",
                training_completed=True,
                risk_score=10,
                status="ACTIVE"
            )
            assert employee.department == dept

    def test_employee_employment_types(self):
        """Test employment type values."""
        for emp_type in ["Employee", "Contingent"]:
            employee = Employee(
                employee_id="EMP-001",
                full_name="Test User",
                email="test@company.com",
                department="Core Banking",
                role="Engineer",
                employment_type=emp_type,
                work_mode="Office",
                city="New York",
                country="USA",
                training_completed=True,
                risk_score=10,
                status="ACTIVE"
            )
            assert employee.employment_type == emp_type

    def test_employee_work_modes(self):
        """Test work mode values."""
        for mode in ["Office", "Remote"]:
            employee = Employee(
                employee_id="EMP-001",
                full_name="Test User",
                email="test@company.com",
                department="Core Banking",
                role="Engineer",
                employment_type="Employee",
                work_mode=mode,
                city="New York",
                country="USA",
                training_completed=True,
                risk_score=10,
                status="ACTIVE"
            )
            assert employee.work_mode == mode

    def test_employee_status_values(self):
        """Test employee status values."""
        for status in ["ACTIVE", "FROZEN"]:
            employee = Employee(
                employee_id="EMP-001",
                full_name="Test User",
                email="test@company.com",
                department="Core Banking",
                role="Engineer",
                employment_type="Employee",
                work_mode="Office",
                city="New York",
                country="USA",
                training_completed=True,
                risk_score=10,
                status=status
            )
            assert employee.status == status

    def test_employee_risk_score_range(self):
        """Test risk score boundaries."""
        # Test minimum
        employee = Employee(
            employee_id="EMP-001",
            full_name="Test User",
            email="test@company.com",
            department="Core Banking",
            role="Engineer",
            employment_type="Employee",
            work_mode="Office",
            city="New York",
            country="USA",
            training_completed=True,
            risk_score=0,
            status="ACTIVE"
        )
        assert employee.risk_score == 0

        # Test maximum
        employee.risk_score = 100
        assert employee.risk_score == 100

    def test_employee_training_completed_boolean(self):
        """Test training_completed as boolean."""
        for completed in [True, False]:
            employee = Employee(
                employee_id="EMP-001",
                full_name="Test User",
                email="test@company.com",
                department="Core Banking",
                role="Engineer",
                employment_type="Employee",
                work_mode="Office",
                city="New York",
                country="USA",
                training_completed=completed,
                risk_score=10,
                status="ACTIVE"
            )
            assert employee.training_completed == completed


class TestDevice:
    """Tests for the Device dataclass."""

    def test_device_creation(self):
        """Test creating a Device instance with all required fields."""
        device = Device(
            device_id="DEV-001",
            hostname="FIN-MBP-4821",
            employee_id="EMP-001",
            employee_name="John Doe",
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

        assert device.device_id == "DEV-001"
        assert device.hostname == "FIN-MBP-4821"
        assert device.employee_id == "EMP-001"
        assert device.employee_name == "John Doe"
        assert device.device_type == "Laptop"
        assert device.os_name == "macOS 15.2"
        assert device.employment_type == "Employee"
        assert device.work_mode == "Office"
        assert device.ip_address == "10.0.0.1"
        assert device.city == "New York"
        assert device.country == "USA"
        assert device.lat == 40.7128
        assert device.lon == -74.0060
        assert device.compliance_status == "Compliant"
        assert device.edr_status == "Protected"
        assert device.isolated is False

    def test_device_hostname_formats(self):
        """Test realistic corporate hostname formats."""
        hostnames = [
            "FIN-MBP-4821",
            "PAY-WIN-9034",
            "SEC-LNX-1172",
            "OPS-MBP-6309"
        ]

        for hostname in hostnames:
            device = Device(
                device_id="DEV-001",
                hostname=hostname,
                employee_id="EMP-001",
                employee_name="John Doe",
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
            assert device.hostname == hostname

    def test_device_types(self):
        """Test device type values."""
        for dtype in ["Laptop", "Workstation", "Server", "Mobile"]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
                device_type=dtype,
                os_name="Linux",
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
            assert device.device_type == dtype

    def test_os_names(self):
        """Test OS name values."""
        os_names = ["macOS 15.2", "Windows 11 24H2", "Ubuntu 24.04 LTS", "iOS 18.1"]

        for os_name in os_names:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
                device_type="Laptop",
                os_name=os_name,
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
            assert device.os_name == os_name

    def test_device_employment_types(self):
        """Test device employment type values."""
        for emp_type in ["Employee", "Contingent"]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
                device_type="Laptop",
                os_name="macOS 15.2",
                employment_type=emp_type,
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
            assert device.employment_type == emp_type

    def test_device_work_modes(self):
        """Test device work mode values."""
        for mode in ["Office", "Remote"]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
                device_type="Laptop",
                os_name="macOS 15.2",
                employment_type="Employee",
                work_mode=mode,
                ip_address="10.0.0.1",
                city="New York",
                country="USA",
                lat=40.7128,
                lon=-74.0060,
                compliance_status="Compliant",
                edr_status="Protected",
                isolated=False
            )
            assert device.work_mode == mode

    def test_device_compliance_status(self):
        """Test compliance status values."""
        for status in ["Compliant", "Exceptions", "Non-Compliant"]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
                device_type="Laptop",
                os_name="macOS 15.2",
                employment_type="Employee",
                work_mode="Office",
                ip_address="10.0.0.1",
                city="New York",
                country="USA",
                lat=40.7128,
                lon=-74.0060,
                compliance_status=status,
                edr_status="Protected",
                isolated=False
            )
            assert device.compliance_status == status

    def test_device_edr_status(self):
        """Test EDR status values."""
        for status in ["Protected", "Outdated Agent", "Tamper Alert"]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
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
                edr_status=status,
                isolated=False
            )
            assert device.edr_status == status

    def test_device_isolated_boolean(self):
        """Test isolated as boolean."""
        for isolated in [True, False]:
            device = Device(
                device_id="DEV-001",
                hostname="TEST-001",
                employee_id="EMP-001",
                employee_name="John Doe",
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
                isolated=isolated
            )
            assert device.isolated == isolated

    def test_device_coordinates(self):
        """Test lat/lon as float values."""
        device = Device(
            device_id="DEV-001",
            hostname="TEST-001",
            employee_id="EMP-001",
            employee_name="John Doe",
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
        assert isinstance(device.lat, float)
        assert isinstance(device.lon, float)
        assert device.lat == 40.7128
        assert device.lon == -74.0060


if __name__ == "__main__":
    pytest.main([__file__, "-v"])