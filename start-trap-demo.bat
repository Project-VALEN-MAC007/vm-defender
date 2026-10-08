@echo off
rem Start the TRAP demo: regenerate demo data, then run the deploy agent and dashboard
cd /d "%~dp0"
echo Generating demo data...
python generate_demo_data.py >nul
if errorlevel 1 (echo generate_demo_data.py failed & pause & exit /b 1)
start "TRAP deploy agent (demo)" cmd /k python run_deploy_agent.py --config evidence/demo/deploy-agent.json
start "TRAP dashboard (demo)" cmd /k python run_dashboard.py --config config/mimic.demo.json
