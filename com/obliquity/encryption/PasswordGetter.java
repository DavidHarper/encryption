package com.obliquity.encryption;

import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.Console;

import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class PasswordGetter {
	public char[] getPassword(String prompt, String verify) throws PasswordMismatchException {
		if (GraphicsEnvironment.isHeadless())
			return getPasswordFromConsole(prompt, verify);
		else
			return getPasswordFromGUI(prompt, verify);
	}
	
	public char[] getPassword(String prompt) throws PasswordMismatchException {
		return getPassword(prompt, null);
	}
	
	public char[] getPasswordFromConsole(String prompt, String verify) throws PasswordMismatchException {
		Console console = System.console();
		
		if (console == null)
			return null;
		
		char[] password = console.readPassword(prompt);
		
		return (verify == null) ? password : verifyPassword(password, console.readPassword(verify));
	}
	
	public char[] getPasswordFromConsole(String prompt) throws PasswordMismatchException {
		return getPasswordFromConsole(prompt, null);
	}
	
	public char[] getPasswordFromGUI(String prompt, String verify) throws PasswordMismatchException {
		PasswordPanel panel = new PasswordPanel(prompt, verify);
		
		JOptionPane optionPane = new JOptionPane(panel, JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
		
		JDialog dialog = optionPane.createDialog("Enter the password");
		
		dialog.setVisible(true);
		
		Object value = optionPane.getValue();
		
		int rc = (value instanceof Integer) ? ((Integer)value).intValue() : -1;
		
		if (rc != JOptionPane.OK_OPTION)
			return null;
		
		char[] password = panel.getPassword();
		
		return (verify == null) ? password : verifyPassword(password, panel.getVerificationPassword());
	}
	
	public char[] getPasswordFromGUI(String prompt) throws PasswordMismatchException {
		return getPasswordFromGUI(prompt, null);
	}
	
	private char[] verifyPassword(char[] password1, char[] password2) throws PasswordMismatchException {
		boolean match = comparePasswords(password1, password2);
		
		if (password2 != null)
			for (int i = 0; i < password2.length; i++)
				password2[i] = '\000';
		
		if (match)
			return password1;
		else
			throw new PasswordMismatchException("Password mismatch");
	}
	
	private boolean comparePasswords(char[] password1, char[] password2) {
		if (password1 == null || password2 == null || password1.length != password2.length)
			return false;
		
		for (int i = 0; i < password1.length; i++)
			if (password1[i] != password2[i])
				return false;
		
		return true;
	}
	
	class PasswordPanel extends JPanel {
		private JPasswordField pwField1 = new JPasswordField(50);
		private JPasswordField pwField2;
		
		public PasswordPanel(String prompt, String verify) {
			super(new GridBagLayout());

			GridBagConstraints c = new GridBagConstraints();
			
			c.insets = new Insets(2, 2, 2, 2);

			c.anchor = GridBagConstraints.WEST;
			c.gridwidth = GridBagConstraints.REMAINDER;
			c.weightx = 0.0;

			c.gridwidth = 1;
			c.anchor = GridBagConstraints.EAST;
			c.fill = GridBagConstraints.NONE;
			c.weightx = 0.0;
			add(new JLabel(prompt), c);

			c.anchor = GridBagConstraints.EAST;
			c.fill = GridBagConstraints.HORIZONTAL;
			c.gridwidth = GridBagConstraints.REMAINDER;
			c.weightx = 1.0;
			add(pwField1, c);
			
			pwField1.setFocusable(true);
			
			if (verify != null) {
				pwField2 = new JPasswordField(50);

				c.gridwidth = 1;
				c.fill = GridBagConstraints.NONE;
				c.anchor = GridBagConstraints.EAST;
				c.weightx = 0.0;

				add(new JLabel(verify), c);

				c.anchor = GridBagConstraints.EAST;
				c.fill = GridBagConstraints.HORIZONTAL;
				c.gridwidth = GridBagConstraints.REMAINDER;
				c.weightx = 1.0;
				add(pwField2, c);
				
				pwField2.setFocusable(true);
			}
			
			pwField1.addComponentListener(new ComponentAdapter() {  
			   public void componentShown(ComponentEvent ce) {  
				   pwField1.requestFocus();  
			   }  
			 });
		}
				
		public char[] getPassword() {
			return pwField1.getPassword();
		}
		
		public char[] getVerificationPassword() {
			return (pwField2 == null) ? null : pwField2.getPassword();
		}
	}
	
	public static void main(String[] args) {
		PasswordGetter getter = new PasswordGetter();
		
		try {
			char[] password = getter.getPassword("Enter your password: ");
			
			if (password == null) {
				System.out.println("No password was provided");
			} else {
				String pw = new String(password);
			
				System.out.println("Password was \"" + pw + "\"");
			}
			
			password = getter.getPassword("Enter your password: ", "Re-enter your password: ");
			
			if (password == null) {
				System.out.println("No password was provided");
			} else {			
				String pw = new String(password);
			
				System.out.println("Password was \"" + pw + "\"");
			}
		} catch (PasswordMismatchException e) {
			e.printStackTrace();
		}
		
		System.exit(0);
	}
}
