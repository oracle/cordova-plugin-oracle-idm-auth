package oracle.idm.auth.plugin.util;

import android.content.res.Resources;

public enum  ResourceHelper {
  INSTANCE;

  public void init(Resources resources,
                   String packageName) {
    _resources = resources;
    _packageName = packageName;
  }

  public int getIdentifier(String name) {
    return  _resources.getIdentifier(name, _ID, _packageName);
  }

  public String getString(String name) {
    return _resources.getString(_resources.getIdentifier(name, _STRING, _packageName));
  }

  public int getLayout(String name) {
    return  _resources.getIdentifier(name, _LAYOUT, _packageName);
  }

  public int getColor(String name) {
    return  _resources.getIdentifier(name, "color", _packageName);
  }

  public int getDrawable(String name) {
    return  _resources.getIdentifier(name, "drawable", _packageName);
  }

  private Resources _resources;
  private String _packageName;

  private static final String _ID = "id";
  private static final String _LAYOUT = "layout";
  private static final String _STRING = "string";
}
