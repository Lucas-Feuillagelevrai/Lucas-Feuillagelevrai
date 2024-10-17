#include "ProcessSelector.hpp"
#include <string>
#include <vector>
#include <optional>
#include <tlhelp32.h>
#include <iostream>


namespace
{
	struct ProcessInfo
	{
		std::wstring name;
		std::wstring window_name;
		DWORD pid;
	};
	std::vector<ProcessInfo> processes{};
	bool update_processes(const std::wstring& name);
	bool print_process_list();
	DWORD get_pid_by_index(std::uint32_t index);
	void ask_proc_name();


	struct Process
	{
		DWORD pid;
		HWND window;
	};

	BOOL CALLBACK EnumWindowsCallback(_In_ HWND hwnd, _In_ LPARAM lParam)
	{
		Process* p_process = (Process*)lParam;
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == p_process->pid
			&& GetWindow(hwnd, GW_OWNER) == NULL
			&& IsWindowVisible(hwnd)
			&& GetConsoleWindow() != hwnd
			) {
			p_process->window = hwnd;
			return FALSE;
		}
		return TRUE;
	}

	HWND getProcessWindow(DWORD pid)
	{
		Process process = { pid, nullptr };
		EnumWindows(&EnumWindowsCallback, (LPARAM)&process);
		return process.window;
	}

	std::wstring getWindowName(HWND hwnd)
	{
		if (!hwnd) return L"";
		wchar_t str[MAX_PATH];
		GetWindowText(hwnd, str, MAX_PATH);
		return std::wstring(str);
	}

	bool update_processes(const std::wstring& name)
	{
		if (name.empty()) return false;
		HANDLE h_processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!h_processes_snapshot) return false;

		std::vector<ProcessInfo> new_processes{};
		PROCESSENTRY32 current_process_entry{.dwSize = sizeof(PROCESSENTRY32)};
		if (Process32First(h_processes_snapshot, &current_process_entry))
		{
			while (Process32Next(h_processes_snapshot, &current_process_entry))
			{
				if (!current_process_entry.th32ProcessID || !std::wcslen(current_process_entry.szExeFile)) continue;
				std::wstring procname = current_process_entry.szExeFile;
				std::wstring window_name = getWindowName(getProcessWindow(current_process_entry.th32ProcessID));
				if (procname.find(name) == std::wstring::npos) continue;
				new_processes.push_back({ std::move(procname), window_name, current_process_entry.th32ProcessID });
			}
		}

		processes = std::move(new_processes);

		CloseHandle(h_processes_snapshot);
		return !processes.empty();
	}


	void ask_proc_name()
	{
		std::wstring input = L"javaw";
		while (!update_processes(input))
		{
			std::wcout << L"No process found for: " << input << L"\n";
			break;
		}
	}
}

DWORD ProcessSelector::ask_pid()
{
	while (true)
	{
		processes.clear();
		ask_proc_name();

		for (const auto& process : processes)
		{
			if (process.window_name.find(L"Paladium -") == 0)
			{
				std::cout << "Process found!" << std::endl;
				return process.pid;
			}
		}

		std::cout << "Process not found! Start Paladium please." << std::endl;
	}
	return 0;
}
