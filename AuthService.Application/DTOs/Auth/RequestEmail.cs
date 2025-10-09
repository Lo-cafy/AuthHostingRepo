using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Application.DTOs.Auth
{
    public class RequestMail
    {
        public string ToEmail { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string ViewName { get; set; } = string.Empty;
        public object ModelJson { get; set; } = new object(); 
    }
}
