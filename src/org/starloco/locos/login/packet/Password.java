package org.starloco.locos.login.packet;

import org.starloco.locos.kernel.Config;
import org.starloco.locos.login.LoginClient;
import org.starloco.locos.login.LoginClient.Status;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Password
{

  static void verify(LoginClient client, String pass)
  {
    InetAddress inetAddress=((InetSocketAddress)client.getIoSession().getRemoteAddress()).getAddress();
    String IP=inetAddress.getHostAddress();

    if(!Config.loginServer.authorizedIp.contains(IP))
    {
      String clientPass=decryptPassword(pass,client.getKey());
      clientPass=CryptSHA512(clientPass);
      if(!clientPass.equals(client.getAccount().getPass()))
      {
        client.send("AlEf");
        client.kick();
        return;
      }
    }
    else
    {
      client.setMaintain();
    }

    client.setStatus(Status.SERVER);
  }

  private static String decryptPassword(String pass, String key)
  {
    if(pass.startsWith("#1"))
      pass=pass.substring(2);
    String chain="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

    char PPass,PKey;
    int APass,AKey,ANB,ANB2,somme1,somme2;

    String decrypted="";

    for(int i=0;i<pass.length();i+=2)
    {
      PKey=key.charAt(i/2);
      ANB=chain.indexOf(pass.charAt(i));
      ANB2=chain.indexOf(pass.charAt(i+1));

      somme1=ANB+chain.length();
      somme2=ANB2+chain.length();

      APass=somme1-(int)PKey;
      if(APass<0)
        APass+=64;
      APass*=16;

      AKey=somme2-(int)PKey;
      if(AKey<0)
        AKey+=64;

      PPass=(char)(APass+AKey);

      decrypted+=PPass;
    }

    return decrypted;
  }

  @SuppressWarnings("deprecation")
  public static String CryptSHA512(String message)
  {
    MessageDigest md;
    try
    {
      md=MessageDigest.getInstance("SHA-512");

      md.update(message.getBytes());
      byte[] mb=md.digest();
      String out="";
      for(int i=0;i<mb.length;i++)
      {
        byte temp=mb[i];
        String s=Integer.toHexString(new Byte(temp));
        while(s.length()<2)
        {
          s="0"+s;
        }
        s=s.substring(s.length()-2);
        out+=s;
      }
      return out;

    }
    catch(NoSuchAlgorithmException e)
    {
      e.printStackTrace();
    }
    return null;
  }
}
