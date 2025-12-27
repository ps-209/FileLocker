using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using HandyControl.Controls;
using Window = System.Windows.Window;
//using Window = HandyControl.Controls.Window;
namespace FileLocker
{
    /// <summary>
    /// PasswordWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class PasswordWindow : Window
    {
        public string Password => PasswordInput.Password;
        public PasswordWindow()
        {
            InitializeComponent();
            this.MouseLeftButtonDown += (s, e) => {
                if (e.LeftButton == MouseButtonState.Pressed) this.DragMove();
            };
        }
        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = true; // 창을 닫으며 true 반환
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false; // 창을 닫으며 false 반환
        }
    }
}
