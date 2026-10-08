@echo off
rem Start the TRAP demo: regenerate demo data, then run the deploy agent and dashboard
cd /d "%~dp0"
rem Close windows left over from an earlier run so the new code is served
taskkill /FI "WINDOWTITLE eq TRAP dashboard (demo)*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq TRAP deploy agent (demo)*" /T /F >nul 2>&1
echo Generating demo data...
python generate_demo_data.py >nul
if errorlevel 1 (echo generate_demo_data.py failed & pause & exit /b 1)
start "TRAP deploy agent (demo)" cmd /k python run_deploy_agent.py --config evidence/demo/deploy-agent.json
start "TRAP dashboard (demo)" cmd /k python run_dashboard.py --config config/trap.demo.json
