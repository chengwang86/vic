Test 6-16 - Verify vic-machine configure
=======

# Purpose:
Verify vic-machine configure

# References:
* vic-machine-linux create -h

# Environment:
This test requires that a vSphere server is running and available
This test requires that a syslog server is running and available

# Test Steps
1. Deploy VCH
2. Configure VCH
3. VCH still function well
4. Check the debug state of the VCH
5. Check the debug state of an existing containerVM
6. Configure the VCH by setting the debug state to 0
7. Check the debug state of the VCH
8. Check the debug state of the existing containerVM
9. Create a new container and check the debug state of it

# Expected Outcome
* All steps should succeed