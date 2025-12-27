using HandyControl.Controls;
using HandyControl.Data;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using File = System.IO.File;
using Window = HandyControl.Controls.Window;

namespace FileLocker
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    [SupportedOSPlatform("windows7.0")]
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            mode_group.IsEnabled = false; //기본 모드설정 비활성화
        }
        private void OpenButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            // 2. 옵션 설정 (선택 사항)
            openFileDialog.Title = "파일을 선택해 주세요"; // 창 제목
            openFileDialog.Filter = "모든 파일 (*.*)|*.*|실행 파일 (*.exe)|*.exe|이미지 파일 (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg"; // 확장자 필터
            openFileDialog.InitialDirectory = @"C:\"; // 초기 열리는 폴더 경로

            // 3. 창 띄우고 결과 받기
            // ShowDialog()가 true를 반환하면 사용자가 파일을 선택하고 '열기'를 누른 것입니다.
            if (openFileDialog.ShowDialog() == true)
            {
                dir_box.Text = openFileDialog.FileName;
                ModeAutoSelect();
            }

        }
        private void dir_box_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                dir_box.Text = files[0]; // 첫 번째 항목의 경로 입력
                ModeAutoSelect();
            }
        }
        private void dir_box_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }
        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            //파일 검증
            string file_path = dir_box.Text;
            string mode = this.lockButton.IsChecked == true ? "Lock" : "Unlock";
            bool isLockMode = this.lockButton.IsChecked == true;

            LockStepBar.StepIndex = 0;
            speed_text.Text = "0 MB / 0 MB";

            if (string.IsNullOrWhiteSpace(file_path) || (!File.Exists(file_path) && !Directory.Exists(file_path)))
            {
                string msi = "유효한 파일이나 폴더를 선택해 주세요.";
                Growl.Warning(new GrowlInfo { Message = msi, ShowDateTime = false });
                return;
            }
            if(!isLockMode && !file_path.EndsWith(".lock", StringComparison.OrdinalIgnoreCase))
            {
                string msi = "일반 파일을 언락할 수 없습니다.";
                Growl.Warning(new GrowlInfo { Message = msi, ShowDateTime = false });
                return;
            }

            //비번 입력
            PasswordWindow pwWin = new PasswordWindow();
            pwWin.Owner = this;
            if (pwWin.ShowDialog() == false)
            {
                string msi = "작업이 취소되었습니다.";
                Growl.Info(new GrowlInfo { Message = msi, ShowDateTime = false });
                return;
            }
            string password = pwWin.Password;

            //작업
            long totalSize = 0;

            DateTime startTime = DateTime.Now;

            Locker.ProgressCallback progressAction = (progress) =>
            {
                Dispatcher.Invoke(() =>
                {
                    // [UI - StepBar] 1.0이 들어와도 최대 4단계까지만 표시 (전체 5단계 중)
                    int currentStep = (int)(progress * 3) + 1; // 0.0~1.0 -> 1~4단계 매핑
                    LockStepBar.StepIndex = Math.Min(currentStep, 4);

                    // [Data - MB/s] 실제 처리 용량 계산
                    double currentMB = (totalSize * progress) / 1024.0 / 1024.0;
                    double totalMB = totalSize / 1024.0 / 1024.0;

                    // 속도 계산
                    double elapsed = (DateTime.Now - startTime).TotalSeconds;
                    double speed = elapsed > 0 ? currentMB / elapsed : 0;

                    // 텍스트 업데이트 (예: 120.5 MB / 500.0 MB (24.1 MB/s))
                    speed_text.Text = $"{currentMB:F1} MB / {totalMB:F1} MB ({speed:F1} MB/s)";
                });
            };
            try
            {
                byte result;
                LockStepBar.StepIndex = 1;
                start_button.IsEnabled = false;
                if (isLockMode)
                {
                    totalSize = Directory.Exists(file_path) ? GetDirectorySize(file_path) : new FileInfo(file_path).Length;
                    result = await Task.Run(() => Locker.LockerEngine.dll_locking(file_path, password, totalSize, progressAction));
                }
                else
                {
                    totalSize = new FileInfo(file_path).Length;
                    result = await Task.Run(() => Locker.LockerEngine.dll_unlocking(file_path, password, totalSize ,progressAction));
                }
                password = string.Empty;
                LockStepBar.StepIndex = 5;
                double totalMB = totalSize / 1024.0 / 1024.0;
                speed_text.Text = $"{totalMB:F1} MB / {totalMB:F1} MB (완료)";
                ProcessComplete(result);
            }
            catch (DllNotFoundException)
            {
                Growl.Error(new GrowlInfo { Message = "암호화 엔진 DLL을 찾을 수 없습니다", ShowDateTime = false });
            }
            finally
            {
                start_button.IsEnabled = true;
            }
        }
        private void ModeAutoSelect() //파일이면서 .lock으로 끝나는 파일일시
        {
            string file_path = dir_box.Text;
            bool isFile = File.Exists(file_path);
            if(isFile == true && file_path.EndsWith(".lock", StringComparison.OrdinalIgnoreCase))
            {
                unlockButton.IsChecked = true;
                mode_group.IsEnabled = true;
            }
            else //폴더거나 일반 파일일 경우
            {
                lockButton.IsChecked = true;
                mode_group.IsEnabled = false;
            }
        }
        private void ProcessComplete(byte code) //완료 메세지 표기
        {
            string msi = code switch
            {
                0 => "성공적으로 완료했습니다.",
                1 => "대상 파일/폴더를 찾을 수 없습니다.",
                2 => "데이터 읽기에 실패했습니다.",
                3 => "암호화/복호화에 실패했습니다.",
                4 => "오류 복구 인코딩/디코딩에 실패했습니다.",
                5 => "파일 쓰기/삭제에 실패했습니다.",
                6 => "멀티스레드 처리에 오류가 발생했습니다.",
                _ => "알 수 없는 오류가 발생했습니다."
            };
            if (code == 0)
            {
                Growl.Success(new GrowlInfo { Message = msi, ShowDateTime = false });

            }
            else
            {
                Growl.Error(new GrowlInfo { Message = msi, ShowDateTime = false });
            }
        }
        private long GetDirectorySize(string path)
        {
            return Directory.GetFiles(path, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length);
        }
    }
}
