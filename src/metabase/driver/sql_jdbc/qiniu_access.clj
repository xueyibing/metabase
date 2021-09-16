(ns metabase.driver.sql-jdbc.qiniu-access
    (:require [clojure.set :as set]
      [metabase.api.common :as api]
      [clojure.tools.logging :as log]
      [metabase.util.i18n :refer [deferred-trs trs]]
      [metabase.models.user :refer [User]]
      [metabase.models.table :refer [Table]]
      [metabase.models.field :refer [Field]]
      [metabase.util.schema :as su]
      [schema.core :as s]
      [toucan.db :as db]
      ))

;获取用户所有属性
(defn getUserAttributes [user_id]
      (first (db/select-field :login_attributes User :id user_id, {:limit 1}))
      )
;获取用户属性对应的key
(defn getUserAttributeByUid [user_id attr_name]
      (let [attrs (first (db/select-field :login_attributes User :id user_id, {:limit 1}))
            attr (get attrs attr_name)]
           attr)
      )
;获取表名
(defn getTableName [table_id]
      (db/select-field :name Table :id table_id, {:limit 1})
      )
;获取字段名
(defn getFieldName [field_id]
      (first (db/select-field :name Field :id field_id, {:limit 1}))
      )

;获取用户所有的权限策略
(defn getPolicy [user_id]

      (db/query {:select [:t3.name :t1.attribute_remappings]
                 :from   [[:group_table_access_policy :t1]]
                 :join   [[:permissions_group_membership :t2] [:= :t1.group_id :t2.group_id]
                          [:metabase_table :t3] [:= :t1.group_id :t3.id]]
                 :where  [:= :t2.user_id user_id]
                 }
                )
      )

(defn replaceEqualItem[sql v user_id role]
      (let
        [
         item_pat (re-pattern "\\[\\s*([\\.A-Za-z0-9_-]+\\s*=\\s*'?(\\$\\{\\s*([\\.A-Za-z0-9_-]+)\\s*\\})'?)\\s*\\]")
         pat_vec (re-find item_pat v)
         condition_bracket (nth pat_vec 0)
         condition (nth pat_vec 1)
         attr_name_curly (nth pat_vec 2)
         attr_name (nth pat_vec 3)
         attr_value (getUserAttributeByUid user_id attr_name)
         new_condition (if (or (= role "admin") (= role "business"))
                         (str "1=1")
                         (if (nil? attr_value)
                           (str "1=0")
                           (clojure.string/replace condition attr_name_curly (clojure.string/replace attr_value " " ""))))]

        (clojure.string/replace sql condition_bracket new_condition)
        )
      )

(defn replaceInItem[sql v user_id role]
      (let
        [
         item_pat (re-pattern "\\[\\s*([\\.A-Za-z0-9_-]+\\s*in\\s*('?\\$\\{\\s*([\\.A-Za-z0-9_-]+)\\s*\\}'?))\\s*\\]")
         pat_vec (re-find item_pat v)
         condition_bracket (nth pat_vec 0)
         condition (nth pat_vec 1)
         attr_name_curly (nth pat_vec 2)
         attr_name (nth pat_vec 3)
         attr_value (getUserAttributeByUid user_id attr_name)
         new_condition (if (or (= role "admin") (= role "business"))
                         (str "1=1")
                         (if (nil? attr_value)
                           (str "1=0")
                           (
                             let [attr_value_arr (clojure.string/split (clojure.string/replace attr_value " " "") #",")
                                  matched (re-matches #"'.+'" attr_name_curly)
                                  attr_final (if matched (str "('" (clojure.string/join "','" attr_value_arr) "')" )
                                                         (str "(" (clojure.string/join "," attr_value_arr) ")"))
                                  ]

                                 (clojure.string/replace condition attr_name_curly attr_final))))]
        (clojure.string/replace sql condition_bracket new_condition))

      )

(defn recurDo [cons sql user_id role replaceFn]
      (defn recurDo0 [cons sql]
            (if (peek cons)
              (let [item (peek cons)
                    sql (replaceFn sql item user_id role)]
                   (recurDo0 (pop cons) sql ))
              sql))
      (recurDo0 cons sql)
      )


(defn replaceCondition [original_sql user_id role]
      (let
        [
         equal_pat (re-pattern "\\[\\s*[\\.A-Za-z0-9_-]+\\s*=\\s*'?\\$\\{\\s*[\\.A-Za-z0-9_-]+\\s*\\}'?\\s*\\]")
         equal_cons (re-seq equal_pat original_sql)
         sql (recurDo (apply list equal_cons) original_sql user_id role replaceEqualItem)
         in_pat (re-pattern "\\[\\s*[\\.A-Za-z0-9_-]+\\s*in\\s*'?\\$\\{\\s*[\\.A-Za-z0-9_-]+\\s*\\}'?\\s*\\]")
         in_cons (re-seq in_pat sql)
         sql (recurDo (apply list in_cons) sql user_id role replaceInItem)]
        sql)
      )

(defn handleAccess [original_sql]
      (log/info "original_sql:" original_sql)
      (let [user_id api/*current-user-id*
            role (if api/*is-superuser?* (str "admin") (getUserAttributeByUid user_id "role"))
            sql (replaceCondition original_sql user_id role)]
           (log/info "new_sql:" sql "user_id:" user_id  "role:" role)
           sql
           )
      )
