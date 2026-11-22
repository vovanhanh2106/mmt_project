"""Dịch vụ Windows (LocalSystem). Cài: python -m ogk_agent service install. KHÔNG ẩn dịch vụ: hiển thị bình thường trong services.msc."""
import logging, servicemanager, socket, sys, win32event, win32service, win32serviceutil
from . import config as C


class OGKService(win32serviceutil.ServiceFramework):
    _svc_name_ = "OpenGuardKids"
    _svc_display_name_ = "OpenGuard Kids – hỗ trợ quản lý thời gian dùng máy"
    _svc_description_ = "Công cụ đồng hành giúp phụ huynh và trẻ thống nhất thời gian dùng máy. Biểu tượng khay hệ thống luôn hiển thị."

    def __init__(self, args):
        super().__init__(args)
        self.hStop = win32event.CreateEvent(None, 0, 0, None)
        self.rt = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.rt: self.rt.stop.set()
        win32event.SetEvent(self.hStop)

    def SvcDoRun(self):
        logging.basicConfig(filename=str(C.home() / "agent.log"), level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        from .runtime import AgentRuntime
        self.rt = AgentRuntime()
        self.rt.run()


def main(argv):
    if len(argv) == 1:
        servicemanager.Initialize(); servicemanager.PrepareToHostSingle(OGKService); servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(OGKService, argv=["ogk"] + argv[1:])
