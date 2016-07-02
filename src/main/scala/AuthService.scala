package codecraft.auth

import akka.actor.ActorSystem
import codecraft.auth._
import codecraft.platform.amqp.{AmqpCloud, RoutingInfo}
import codecraft.platform.ICloud
import codecraft.user._
import io.github.nremond.SecureHash
import scala.concurrent.duration._
import scala.util.{Try, Success, Failure}

final case class AuthRecord(
  passwordHash: String
)

case class AuthService(cloud: ICloud) extends IAuthService {
  // Maps from email to AuthRecord
  var auths = Map.empty[String, AuthRecord]
  // Maps from token to email
  var tokenToEmail = Map.empty[String, String]
  // Maps from email to token
  var emailToToken = Map.empty[String, String]

  // email to (roleId to Set[permission ids]
  var authRoles = Map.empty[String, Map[String, Set[String]]]

  def uuid = java.util.UUID.randomUUID.toString

  // Not thread safe.
  def invalidateEmailToken(email: String) = {
    emailToToken get email foreach { token =>
      tokenToEmail -= token
    }
    emailToToken -= email
  }

  def generateToken(email: String) = {
    val token = uuid
    emailToToken += (email -> token)
    tokenToEmail += (token -> email)
    token
  }

  def add(cmd: AddAuth): AddAuthReply = this.synchronized {
    auths.get(cmd.email) map { _ =>
      // Already exists.
      AddAuthReply(None, Map.empty, Some("Email already registered"))
    } getOrElse {
      val roles = authRoles.getOrElse(
        cmd.email,
        Map.empty
      ).map {
        case (key, permissions) => (key -> permissions.toList)
      }.toMap

      val passwordHash = SecureHash.createHash(
        cmd.password
      )
      val record = AuthRecord(
        passwordHash
      )

      auths += (cmd.email -> record)

      val token = generateToken(cmd.email)

      AddAuthReply(Some(token), roles, None)
    }
  }

  def addRole(cmd: AddRole) = this.synchronized {
    tokenToEmail get (cmd.token) match {
      case None =>
        AddRoleReply(None, Some("Token is invalid"))
      case Some(email) =>
        // Add the role id to the email's set of roles.
        var roles = authRoles.getOrElse(email, Map.empty[String, Set[String]])
        roles get (cmd.id) match {
          case None =>
            val newRoles = roles + (cmd.id -> Set.empty[String])
            authRoles += (email -> newRoles)
          case _ => ()
        }

        val token = generateToken(email)
        AddRoleReply(Some(token), None)
    }
  }

  def addPermission(cmd: AddPermission) = this.synchronized {
    // First, lookup the email from the token.
    tokenToEmail get (cmd.token) match {
      case None =>
        AddPermissionReply(None, Some("Invalid token"))
      case Some(email) =>
        val token = generateToken(email)

        // Lookup the role.
        authRoles get email match {
          case None =>
            AddPermissionReply(Some(token), Some("Role does not exist"))
          case Some(roles) =>
            // Check if the role exists.
            roles get (cmd.roleId) match {
              case None =>
                AddPermissionReply(Some(token), Some("Role does not exist"))
              case Some(permissionIds) =>
                // Add the permission id to the ids.
                val newRoles = roles + (cmd.roleId -> (permissionIds + cmd.id))
                authRoles += (email -> newRoles)
                AddPermissionReply(Some(token), None)
            }
        }
    }
  }

  def get(cmd: GetAuth): GetAuthReply = this.synchronized {
    auths.get (cmd.email) map { auth =>
      invalidateEmailToken(cmd.email)
      val token = generateToken(cmd.email)
      val roles = authRoles.getOrElse(cmd.email, Map.empty).map{
        case (key, permissions) => (key -> permissions.toList)
      }.toMap

      GetAuthReply(Some(token), roles, None)
    } getOrElse {
      GetAuthReply(None, Map.empty, Some("Auth does not exist"))
    }
  }

  def getPermission(cmd: GetPermission): GetPermissionReply = this.synchronized {
    // First, lookup the email associated with the token.
    tokenToEmail get (cmd.token) match {
      case None =>
        GetPermissionReply(false, None, Some("Invalid token"))
      case Some(email) =>
        val token = generateToken(email)

        authRoles get email match {
          case None => GetPermissionReply(false, Some(token), Some("Role does not exist"))
          case Some(roles) =>
            // Check if the role exists.
            roles get (cmd.roleId) match {
              case None => GetPermissionReply(false, Some(token), Some("Role does not exist"))
              case Some(permissions) =>
                // Check if this id has permission.
                if (permissions contains (cmd.id)) {
                  GetPermissionReply(true, Some(token), None)
                }
                else {
                  GetPermissionReply(false, Some(token), Some("Permission denied"))
                }
            }
        }
    }
  }

  def consumeToken(cmd: ConsumeToken): ConsumeTokenReply = this.synchronized {
    tokenToEmail get (cmd.token) match {
      case None =>
        ConsumeTokenReply(None, Some("Token is invalid"))
      case Some(email) =>
        val token = generateToken(email)
        ConsumeTokenReply(Some(token), None)
    }
  }

  def onError(exn: Throwable) {
    println(s"$exn")
  }
}

object Main {
  val routingInfo = RoutingInfo(
    AuthRoutingGroup.cmdInfo.map {
      case registry => (registry.key, registry)
    } toMap,
    Map(
      AuthRoutingGroup.groupRouting.queueName -> AuthRoutingGroup.groupRouting
    )
  )

  def main(argv: Array[String]) {
    val system = ActorSystem("service")
    val cloud = AmqpCloud(
      system,
      List(
        "amqp://192.168.99.101:5672"
      ),
      routingInfo
    )

    val service = AuthService(cloud)

    import system.dispatcher

    cloud.subscribeCmd(
      "cmd.auth",
      service,
      5 seconds
    ) onComplete {
      case Failure(e) => throw e
      case Success(_) => println("Started service.")
    }
  }
}

